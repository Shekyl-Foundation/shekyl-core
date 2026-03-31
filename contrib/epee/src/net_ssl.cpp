// Copyright (c) 2018-2022, The Monero Project

// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <string.h>
#include <thread>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/cerrno.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/asio/strand.hpp>
#include <condition_variable>
#include <boost/lambda/lambda.hpp>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include "misc_log_ex.h"
#include "net/net_helper.h"
#include "net/net_ssl.h"
#include "file_io_utils.h"
#include "shekyl/shekyl_ffi.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.ssl"


#if BOOST_VERSION >= 107300
  #define MONERO_HOSTNAME_VERIFY boost::asio::ssl::host_name_verification
#else
  #define MONERO_HOSTNAME_VERIFY boost::asio::ssl::rfc2818_verification
#endif

// openssl genrsa -out /tmp/KEY 4096
// openssl req -new -key /tmp/KEY -out /tmp/REQ
// openssl x509 -req -days 999999 -sha256 -in /tmp/REQ -signkey /tmp/KEY -out /tmp/CERT

#ifdef _WIN32
static void add_windows_root_certs(SSL_CTX *ctx) noexcept;
#endif

namespace
{
  struct openssl_bio_free
  {
    void operator()(BIO* ptr) const noexcept
    {
      BIO_free(ptr);
    }
  };
  using openssl_bio = std::unique_ptr<BIO, openssl_bio_free>;

  struct openssl_pkey_free
  {
    void operator()(EVP_PKEY* ptr) const noexcept
    {
      EVP_PKEY_free(ptr);
    }
  };
  using openssl_pkey = std::unique_ptr<EVP_PKEY, openssl_pkey_free>;

  boost::system::error_code load_ca_file(boost::asio::ssl::context& ctx, const std::string& path)
  {
    SSL_CTX* const ssl_ctx = ctx.native_handle();
    if (ssl_ctx == nullptr)
      return {boost::asio::error::invalid_argument};

    if (!SSL_CTX_load_verify_locations(ssl_ctx, path.c_str(), nullptr))
    {
      return boost::system::error_code{
        int(::ERR_get_error()), boost::asio::error::get_ssl_category()
      };
    }
    return boost::system::error_code{};
  }
}

namespace epee
{
namespace net_utils
{


bool create_ssl_certificate(EVP_PKEY *&pkey, X509 *&cert)
{
  MINFO("Generating ECDSA P-256 SSL certificate via Rust (rcgen)");

  ShekylBuffer key_pem{nullptr, 0};
  ShekylBuffer cert_pem{nullptr, 0};

  if (!shekyl_generate_ssl_certificate(&key_pem, &cert_pem))
  {
    MERROR("Rust certificate generation failed");
    return false;
  }

  openssl_bio bio_key{BIO_new_mem_buf(key_pem.ptr, static_cast<int>(key_pem.len))};
  if (!bio_key)
  {
    MERROR("Failed to create BIO for private key PEM");
    shekyl_buffer_free(key_pem.ptr, key_pem.len);
    shekyl_buffer_free(cert_pem.ptr, cert_pem.len);
    return false;
  }

  pkey = PEM_read_bio_PrivateKey(bio_key.get(), nullptr, nullptr, nullptr);
  if (!pkey)
  {
    MERROR("Failed to parse PEM private key: " << ERR_reason_error_string(ERR_get_error()));
    shekyl_buffer_free(key_pem.ptr, key_pem.len);
    shekyl_buffer_free(cert_pem.ptr, cert_pem.len);
    return false;
  }

  openssl_bio bio_cert{BIO_new_mem_buf(cert_pem.ptr, static_cast<int>(cert_pem.len))};
  if (!bio_cert)
  {
    MERROR("Failed to create BIO for certificate PEM");
    EVP_PKEY_free(pkey);
    pkey = nullptr;
    shekyl_buffer_free(key_pem.ptr, key_pem.len);
    shekyl_buffer_free(cert_pem.ptr, cert_pem.len);
    return false;
  }

  cert = PEM_read_bio_X509(bio_cert.get(), nullptr, nullptr, nullptr);
  if (!cert)
  {
    MERROR("Failed to parse PEM certificate: " << ERR_reason_error_string(ERR_get_error()));
    EVP_PKEY_free(pkey);
    pkey = nullptr;
    shekyl_buffer_free(key_pem.ptr, key_pem.len);
    shekyl_buffer_free(cert_pem.ptr, cert_pem.len);
    return false;
  }

  shekyl_buffer_free(key_pem.ptr, key_pem.len);
  shekyl_buffer_free(cert_pem.ptr, cert_pem.len);
  return true;
}

ssl_options_t::ssl_options_t(std::vector<std::vector<std::uint8_t>> fingerprints, std::string ca_path)
  : fingerprints_(std::move(fingerprints)),
    ca_path(std::move(ca_path)),
    auth(),
    support(ssl_support_t::e_ssl_support_enabled),
    verification(ssl_verification_t::user_certificates)
{
  std::sort(fingerprints_.begin(), fingerprints_.end());
}

boost::asio::ssl::context ssl_options_t::create_context() const
{
  // note: this enables a lot of old and insecure protocols, which we
  // promptly disable below - if the result is actually used
  boost::asio::ssl::context ssl_context{boost::asio::ssl::context::sslv23};
  if (!bool(*this))
    return ssl_context;

  // only allow tls v1.2 and up
  ssl_context.set_options(boost::asio::ssl::context::default_workarounds);
  ssl_context.set_options(boost::asio::ssl::context::no_sslv2);
  ssl_context.set_options(boost::asio::ssl::context::no_sslv3);
  ssl_context.set_options(boost::asio::ssl::context::no_tlsv1);
  ssl_context.set_options(boost::asio::ssl::context::no_tlsv1_1);

  SSL_CTX *ctx = ssl_context.native_handle();
  CHECK_AND_ASSERT_THROW_MES(ctx, "Failed to get SSL context");

  // TLS 1.2 cipher suites (AEAD only, ECDHE key exchange)
  SSL_CTX_set_cipher_list(ctx,
    "ECDHE-ECDSA-CHACHA20-POLY1305-SHA256:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-GCM-SHA256");

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  // TLS 1.3 cipher suites (all are AEAD; key exchange is via groups below)
  SSL_CTX_set_ciphersuites(ctx,
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "TLS_AES_128_GCM_SHA256");
#endif

  // Post-quantum hybrid key exchange: prefer ML-KEM-768 + X25519 (FIPS 203),
  // falling back to classical curves if the OpenSSL build lacks PQ support.
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  if (!SSL_CTX_set1_groups_list(ctx,
        "X25519MLKEM768:SecP256r1MLKEM768:X25519:P-256:P-384"))
  {
    MINFO("PQ hybrid key exchange groups not available, using classical groups");
    SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384");
  }
  else
  {
    MINFO("Post-quantum hybrid key exchange enabled (X25519MLKEM768)");
  }
#endif

  SSL_CTX_clear_options(ctx, SSL_OP_LEGACY_SERVER_CONNECT);
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
#ifdef SSL_OP_NO_TICKET
  SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
#endif
#ifdef SSL_OP_NO_RENEGOTIATION
  SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
#endif
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
  SSL_CTX_set_options(ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#endif
#ifdef SSL_OP_NO_COMPRESSION
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
  SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
#endif

  switch (verification)
  {
    case ssl_verification_t::system_ca:
#ifdef _WIN32
      try { add_windows_root_certs(ssl_context.native_handle()); }
      catch (const std::exception &e) { ssl_context.set_default_verify_paths(); }
#else
      ssl_context.set_default_verify_paths();
#endif
      break;
    case ssl_verification_t::user_certificates:
      ssl_context.set_verify_depth(0);
      /* fallthrough */
    case ssl_verification_t::user_ca:
      if (!ca_path.empty())
      {
        const boost::system::error_code err = load_ca_file(ssl_context, ca_path);
        if (err)
          throw boost::system::system_error{err, "Failed to load user CA file at " + ca_path};
      }
      break;
    default:
      break;
  }

  CHECK_AND_ASSERT_THROW_MES(auth.private_key_path.empty() == auth.certificate_path.empty(), "private key and certificate must be either both given or both empty");

  const bool private_key_exists = epee::file_io_utils::is_file_exist(auth.private_key_path);
  const bool certificate_exists = epee::file_io_utils::is_file_exist(auth.certificate_path);
  if (private_key_exists && !certificate_exists) {
    ASSERT_MES_AND_THROW("private key is present, but certificate file '" << auth.certificate_path << "' is missing");
  } else if (!private_key_exists && certificate_exists) {
    ASSERT_MES_AND_THROW("certificate is present, but private key file '" << auth.private_key_path << "' is missing");
  }

  if (auth.private_key_path.empty())
  {
    EVP_PKEY *pkey = nullptr;
    X509 *cert = nullptr;

    CHECK_AND_ASSERT_THROW_MES(create_ssl_certificate(pkey, cert), "Failed to create certificate");
    CHECK_AND_ASSERT_THROW_MES(SSL_CTX_use_certificate(ctx, cert), "Failed to use generated certificate");
    CHECK_AND_ASSERT_THROW_MES(SSL_CTX_use_PrivateKey(ctx, pkey), "Failed to use generated private key");
    X509_free(cert);
    EVP_PKEY_free(pkey);
  }
  else
    auth.use_ssl_certificate(ssl_context);

  return ssl_context;
}

void ssl_authentication_t::use_ssl_certificate(boost::asio::ssl::context &ssl_context) const
{
  try {
    ssl_context.use_private_key_file(private_key_path, boost::asio::ssl::context::pem);
  } catch (const boost::system::system_error&) {
    MERROR("Failed to load private key file '" << private_key_path << "' into SSL context");
    throw;
  }
  ssl_context.use_certificate_chain_file(certificate_path);
}

bool is_ssl(const unsigned char *data, size_t len)
{
  if (len < get_ssl_magic_size())
    return false;

  // https://security.stackexchange.com/questions/34780/checking-client-hello-for-https-classification
  MDEBUG("SSL detection buffer, " << len << " bytes: "
    << (unsigned)(unsigned char)data[0] << " " << (unsigned)(unsigned char)data[1] << " "
    << (unsigned)(unsigned char)data[2] << " " << (unsigned)(unsigned char)data[3] << " "
    << (unsigned)(unsigned char)data[4] << " " << (unsigned)(unsigned char)data[5] << " "
    << (unsigned)(unsigned char)data[6] << " " << (unsigned)(unsigned char)data[7] << " "
    << (unsigned)(unsigned char)data[8]);
  if (data[0] == 0x16) // record
  if (data[1] == 3) // major version
  if (data[5] == 1) // ClientHello
  if (data[6] == 0 && data[3]*256 + data[4] == data[7]*256 + data[8] + 4) // length check
    return true;
  return false;
}

bool ssl_options_t::has_strong_verification(boost::string_ref host) const noexcept
{
  // onion and i2p addresses contain information about the server cert
  // which both authenticates and encrypts
  if (host.ends_with(".onion") || host.ends_with(".i2p"))
    return true;
  switch (verification)
  {
    default:
    case ssl_verification_t::none:
    case ssl_verification_t::system_ca:
      return false;
    case ssl_verification_t::user_certificates:
    case ssl_verification_t::user_ca:
      break;
  }
  return true;
}

bool ssl_options_t::has_fingerprint(boost::asio::ssl::verify_context &ctx) const
{
  // can we check the certificate against a list of fingerprints?
  if (!fingerprints_.empty()) {
    X509_STORE_CTX *sctx = ctx.native_handle();
    if (!sctx)
    {
      MERROR("Error getting verify_context handle");
      return false;
    }

    X509* cert = nullptr;
    const STACK_OF(X509)* chain = X509_STORE_CTX_get_chain(sctx);
    if (!chain || sk_X509_num(chain) < 1 || !(cert = sk_X509_value(chain, 0)))
    {
      MERROR("No certificate found in verify_context");
      return false;
    }

    // buffer for the certificate digest and the size of the result
    std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned int size{ 0 };

    // create the digest from the certificate
    if (!X509_digest(cert, EVP_sha256(), digest.data(), &size)) {
      MERROR("Failed to create certificate fingerprint");
      return false;
    }

    // strip unnecessary bytes from the digest
    digest.resize(size);

    return std::binary_search(fingerprints_.begin(), fingerprints_.end(), digest);
  }

  return false;
}

void ssl_options_t::configure(
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket> &socket,
  boost::asio::ssl::stream_base::handshake_type type,
  const std::string& host) const
{
  socket.next_layer().set_option(boost::asio::ip::tcp::no_delay(true));
  {
    // in case server is doing "virtual" domains, set hostname
    SSL* const ssl_ctx = socket.native_handle();
    if (type == boost::asio::ssl::stream_base::client && !host.empty() && ssl_ctx)
      SSL_set_tlsext_host_name(ssl_ctx, host.c_str());
  }


  /* Using system-wide CA store for client verification is funky - there is
     no expected hostname for server to verify against. If server doesn't have
     specific whitelisted certificates for client, don't require client to
     send certificate at all. */
  const bool no_verification = verification == ssl_verification_t::none ||
    (type == boost::asio::ssl::stream_base::server && fingerprints_.empty() && ca_path.empty());

  /* According to OpenSSL documentation (and SSL specifications), server must
     always send certificate unless "anonymous" cipher mode is used which are
     disabled by default. Either way, the certificate is never inspected. */
  if (no_verification)
    socket.set_verify_mode(boost::asio::ssl::verify_none);
  else
  {
    socket.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert);

    
    socket.set_verify_callback([&](const bool preverified, boost::asio::ssl::verify_context &ctx)
    {
      // preverified means it passed system or user CA check. System CA is never loaded
      // when fingerprints are whitelisted.
      const bool verified = preverified &&
        (verification != ssl_verification_t::system_ca || host.empty() || MONERO_HOSTNAME_VERIFY(host)(preverified, ctx));

      if (!verified && !has_fingerprint(ctx))
      {
        // autodetect will reconnect without SSL - warn and keep connection encrypted
        if (support != ssl_support_t::e_ssl_support_autodetect)
        {
          MERROR("SSL certificate is not in the allowed list, connection dropped");
          return false;
        }
        MWARNING("SSL peer has not been verified");
      }
      return true;
    });
  }
}

bool ssl_options_t::handshake(
  boost::asio::io_context& io_context,
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket> &socket,
  boost::asio::ssl::stream_base::handshake_type type,
  boost::asio::const_buffer buffer,
  const std::string& host,
  std::chrono::milliseconds timeout) const
{
  configure(socket, type, host);

  auto start_handshake = [&]{
    using ec_t = boost::system::error_code;
    using timer_t = boost::asio::steady_timer;
    using strand_t = boost::asio::io_context::strand;
    using socket_t = boost::asio::ip::tcp::socket;

    if (io_context.stopped())
      io_context.restart();
    strand_t strand(io_context);
    timer_t deadline(io_context, timeout);

    struct state_t {
      std::mutex lock;
      std::condition_variable_any condition;
      ec_t result;
      bool wait_timer;
      bool wait_handshake;
      bool cancel_timer;
      bool cancel_handshake;
    };
    state_t state{};

    state.wait_timer = true;
    auto on_timer = [&](const ec_t &ec){
      std::lock_guard<std::mutex> guard(state.lock);
      state.wait_timer = false;
      state.condition.notify_all();
      if (!state.cancel_timer) {
        state.cancel_handshake = true;
        ec_t ec;
        socket.next_layer().cancel(ec);
      }
    };

    state.wait_handshake = true;
    auto on_handshake = [&](const ec_t &ec, size_t bytes_transferred){
      std::lock_guard<std::mutex> guard(state.lock);
      state.wait_handshake = false;
      state.condition.notify_all();
      state.result = ec;
      if (!state.cancel_handshake) {
        state.cancel_timer = true;
        deadline.cancel();
      }
    };

    deadline.async_wait(on_timer);
    boost::asio::post(
      strand,
      [&]{
        socket.async_handshake(
          type,
          boost::asio::buffer(buffer),
          strand.wrap(on_handshake)
        );
      }
    );

    while (!io_context.stopped())
    {
      io_context.poll_one();
      std::lock_guard<std::mutex> guard(state.lock);
      state.condition.wait_for(
        state.lock,
        std::chrono::milliseconds(30),
        [&]{
          return !state.wait_timer && !state.wait_handshake;
        }
      );
      if (!state.wait_timer && !state.wait_handshake)
        break;
    }
    if (state.result.value()) {
      ec_t ec;
      socket.next_layer().shutdown(socket_t::shutdown_both, ec);
      socket.next_layer().close(ec);
    }
    return state.result;
  };
  const auto ec = start_handshake();

  if (ec)
  {
    MERROR("SSL handshake failed, connection dropped: " << ec.message());
    return false;
  }
  MDEBUG("SSL handshake success");
  return true;
}

bool ssl_support_from_string(ssl_support_t &ssl, boost::string_ref s)
{
  if (s == "enabled")
    ssl = epee::net_utils::ssl_support_t::e_ssl_support_enabled;
  else if (s == "disabled")
    ssl = epee::net_utils::ssl_support_t::e_ssl_support_disabled;
  else if (s == "autodetect")
    ssl = epee::net_utils::ssl_support_t::e_ssl_support_autodetect;
  else
    return false;
  return true;
}

boost::system::error_code store_ssl_keys(boost::asio::ssl::context& ssl, const boost::filesystem::path& base)
{
  EVP_PKEY* ssl_key = nullptr;
  X509* ssl_cert = nullptr;
  const auto ctx = ssl.native_handle();
  CHECK_AND_ASSERT_MES(ctx, boost::system::error_code(EINVAL, boost::system::system_category()), "Context is null");
  CHECK_AND_ASSERT_MES(base.has_filename(), boost::system::error_code(EINVAL, boost::system::system_category()), "Need filename");
  std::unique_ptr<SSL, decltype(&SSL_free)> dflt_SSL(SSL_new(ctx), SSL_free);
  if (!dflt_SSL || !(ssl_key = SSL_get_privatekey(dflt_SSL.get())) || !(ssl_cert = SSL_get_certificate(dflt_SSL.get())))
    return {EINVAL, boost::system::system_category()};

  using file_closer = int(std::FILE*);
  boost::system::error_code error{};
  std::unique_ptr<std::FILE, file_closer*> file{nullptr, std::fclose};

  // write key file unencrypted
  {
    const boost::filesystem::path key_file{base.string() + ".key"};
    file.reset(std::fopen(key_file.string().c_str(), "wb"));
    if (!file)
    {
      if (epee::file_io_utils::is_file_exist(key_file.string())) {
        MERROR("Permission denied to overwrite SSL private key file: '" << key_file.string() << "'");
      } else {
        MERROR("Could not open SSL private key file for writing: '" << key_file.string() << "'");
      }

      return {errno, boost::system::system_category()};
    }
    boost::filesystem::permissions(key_file, boost::filesystem::owner_read, error);
    if (error)
      return error;
    if (!PEM_write_PrivateKey(file.get(), ssl_key, nullptr, nullptr, 0, nullptr, nullptr))
      return boost::asio::error::ssl_errors(ERR_get_error());
    if (std::fclose(file.release()) != 0)
      return {errno, boost::system::system_category()};
  }

  // write certificate file in standard SSL X.509 unencrypted
  const boost::filesystem::path cert_file{base.string() + ".crt"};
  file.reset(std::fopen(cert_file.string().c_str(), "wb"));
  if (!file)
    return {errno, boost::system::system_category()};
  const auto cert_perms = (boost::filesystem::owner_read | boost::filesystem::group_read | boost::filesystem::others_read);
  boost::filesystem::permissions(cert_file, cert_perms, error);
  if (error)
    return error;
  if (!PEM_write_X509(file.get(), ssl_cert))
    return boost::asio::error::ssl_errors(ERR_get_error());
  if (std::fclose(file.release()) != 0)
    return {errno, boost::system::system_category()};
  return error;
}

} // namespace
} // namespace

#ifdef _WIN32

// https://stackoverflow.com/questions/40307541
// Because Windows always has to do things wonkily
#include <wincrypt.h>
static void add_windows_root_certs(SSL_CTX *ctx) noexcept
{
    HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
    if (hStore == NULL) {
        return;
    }

    X509_STORE *store = X509_STORE_new();
    PCCERT_CONTEXT pContext = NULL;
    while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL) {
        // convert from DER to internal format
        X509 *x509 = d2i_X509(NULL,
                              (const unsigned char **)&pContext->pbCertEncoded,
                              pContext->cbCertEncoded);
        if(x509 != NULL) {
            X509_STORE_add_cert(store, x509);
            X509_free(x509);
        }
    }

    CertFreeCertificateContext(pContext);
    CertCloseStore(hStore, 0);

    // attach X509_STORE to boost ssl context
    SSL_CTX_set_cert_store(ctx, store);
}
#endif

