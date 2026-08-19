// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Cross-language KAT for the credit-wire attestation verify (CW-3,
// ARCHIVAL_CREDIT_WIRE.md §3-§4). The verify LOGIC is exhaustively tested in Rust
// (shekyl-ffi archival_ffi.rs attestation_verify_tests); what only C++ can prove is
// that the C-side structs in shekyl/shekyl_ffi.h (shekyl_archival_attestation_verify_ctx,
// shekyl_archival_pid_pubkey) marshal byte-identically to the Rust #[repr(C)]
// definitions across the real ABI boundary -- the "byte-identical-or-split" surface.
//
// A single frozen valid one-pass vector, generated once by
// shekyl-ffi::attestation_verify_tests::emit_attestation_verify_kat, is fed back
// through the C structs; a passing verdict proves the layout agrees end to end, and
// each negative control moves exactly one field to prove that field is read where the
// C header says it is. Regenerate + re-paste only if the genesis-frozen wire format
// changes (the emitter's keypair is random, so the bytes differ each run):
//   cargo test -p shekyl-ffi emit_attestation_verify_kat -- --ignored --nocapture

#include "gtest/gtest.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"

namespace
{
std::vector<uint8_t> from_hex(const std::string& h)
{
  std::vector<uint8_t> out;
  out.reserve(h.size() / 2);
  for (size_t i = 0; i + 1 < h.size(); i += 2)
    out.push_back(static_cast<uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
  return out;
}

// Frozen valid one-pass vector (see file header). headers = p_id(32) || shard(8 LE) ||
// epoch(8 LE) || kind(1); p_id is the first 32 bytes of headers; cb_out_key is the
// constant [0x09; 32] the emitter binds; root is attestation_root over the one pass record.
const std::string KAT_HEADERS =
  "ea3b5a69470ab5490a3e7c3395a7e5baade6bab4119a912b1f029e36f8dedbad2a00000000000000e80300000000000001";
const std::string KAT_P_ID =
  "ea3b5a69470ab5490a3e7c3395a7e5baade6bab4119a912b1f029e36f8dedbad";
const std::string KAT_ROOT =
  "6670d3034b0238a27a50c59af256b35f08cb48b3041625b9895e60ea317ad5e5";
// The nonce's first term. RF-D3 replaced the producer's revealed randomness `r` with the
// validated predecessor hash; the TERM IS REPLACED, NOT DROPPED, so keeping the same 32 bytes
// (0x07…) keeps the nonce, the countersignature and the root byte-identical. Only the witness
// blob changes: it no longer transports these bytes, because the verifier already holds the
// predecessor hash as chain state.
const std::string KAT_PREV_BLOCK_HASH =
  "0707070707070707070707070707070707070707070707070707070707070707";
const std::string KAT_CBKEY =
  "0909090909090909090909090909090909090909090909090909090909090909";
const std::string KAT_WITNESS =
  "010000000000000002010000400000001efb5a7508d1057199b7a8eacd7d46fde6cede6d26e66e89c3750f984f5c08be25b16d8997b6f4c9644cf814b22a71adcb606c9fb3a1c8598fbc578496a5fb0fed0c0000fd6f06968adb9be7fc6c40739c6711e04a0a37b8d2469dfe3058dd34540a5ff84cc94fe7a19b14e5777d82c639ea72dc917a4c00f54d891ea2050d72eaec67c9b87e4cef8565c24eff982be91b5587dcf01f50881fadee7cdc46bdef94584007672332d165de859b9c0e70670792e622e33669f8e390ad023ff6472a0ddb5a3882892d9d07968b271d1677b7c4eb59e3dc8c452cb770493349bd205e08c86b691c3472ec6118cc7271e1f7301517bc6c967e779a6c3c0ed99dd087649f254ded4b95bef932c52d2a874503aa589a99f3529694f796d5ae8a67b565d4a76fa6890917662608e5b13c99e9db7f1a1497e7b181bd19d9d2a6bc075aed1f18287cf82bd828deed6fe8c6b885e78d30b4aa76bf1c7734b985be36bd632f8d351b7cdd072f0777e5f2b8889d97576742746be6d26caa0f6426ee2dc27100691b46455c91566d24d703410f5a27f50dc6d7cc5deb7a23140f4d539bbbff357104d174ab804285ffd595a46912f1ac1f3ece6cc7df577c55d1b5b16c6f7e274a9f7a39dd24567e8928953512b05aba61a9fbeab16ec10e4d83ff0f05ec69f783df50bba29e3381c93d4562a173b05f481b87eeacad08aed857e62161ee488c6e5e2ceae4362a47d888e7c8c537556c014bde159bf99c2f30d67e7954b339412bfaf9f58e0d10cf6f7920a1c3373aafd1eaa89f16503351f86083dbe6420fdbe7bb767c31181b22331c7cd9d371fb17de3d064489424d36b2a4485cc06a70e41cb9f487b95d8033330f9c45aac91f65fe1511618c72ab318a562a43ca28f6b18fb0470a7939b144e250b1df34a20ea9ce3ad8976806c93a281c54d84bf712f36291c3c0d216b61c32342f771754724bd64512624fab28e3f3c0b04b228848341b207e798f3eace5072c64643dd4838f22600b80327323d07caf49296591cfe79370ddb23864ff38633d7d1879bb521239f78b1c2345b5ab51357e351a3ab1e811645cddec32ee92bc889f78a10961641560715d94de9686f32b30b6b34f6a098be1296618c811f078882a2b3d1ace7b169e943fa63423429754b938bf3d2dd95f555c2d2b8e6cd3aefc600c1452119acd387cf762fc5c35351795789a3181311af54e04ffcfa6584fedfa58f69180e36137515cbd9acf28ff516baa5c72c37b905b3e53645fe80992ad392155fe2f5e17135cd27f5a8de6957a6322f5d901e2c57d767b8dbca84dddf2cca1a26411dc3fac940459b29bc762cbef111f44d0d689ef8b93a65972ee7771539af4583cf72cbfd67fec6674f8af66ee7d5cb4d6357db6e164c02dc7896c740c1171df7a3ed4fd2d2d12eccea8a43a44fbf6d41fcf9b8441ee418154140ac9ba15313c75d8abada3a444c0350671843987988d80a9da5546e7d0e97cc570f138df005ead9aea3b7d9b6946a03f30ffc423c9e63a80ffe141aff6e61d94be6900cb49dd53bc62fd7208bad696de09c06eb0c12da07d194a9465d037b4399734b22445f193a3dc7c83f7a317e15de3a5851a1f307106a2d40ff80d4b24fbb66e94d38a544af8cdef87c1061bd9f61a8a264d3dc45ffb363c203e65b9d7d71cd086f447515a731d7cefcff3e3bc24b602fdb2a9d64bfe16657d0854aad07aa679a8d83ddc66d7ab646c741249b0c996bd6351b80d4fd53138a4d5b91a2bb2da08d312ec94aa71d9b2eb6c2e832c8f583069cae454b96ac32dbf7342212d7ab073e593c6739cc22a6f5af2857154dc89e695c39e87fa26bbadbb8b1d120b020f2641f21d3474a8fac22220fea7e5a5ea2c597d1f311e4ce726d5932c52ed31a7c44ca920185e24c9e64adaee3d18cabff0085ebc9b762c8bcd58d1413c05dee30e4a7a69c5a0677b11483164e12a462e0e288a6484f84042569b4baf20cb7ac6819bc57e0b130a1450a17a1d3aaea585a717b14fc57deeb4b1cf0e0865ba681ace75c2990fd06da447e56510304fe04c4971061dea6e85cded6cf2b76385400482432f337ad1d98c72d1868539c06fb192626cbc79068f8750bcb73e97e0e64d0f5b2adcf353ce6616fd6f5b71745718edadce31000b6eae30657cf1ee8fc8d289fafc0705d1802347674917f08e1392dfe26f1207a8d0c5ace5364c726f4a5a0014e4858800548ba977c69b9eb9b091e5507e1facf5a7d725d448f31fb3409425e712d1bdbec2d1fd629916efc6a39543d53a4b0c1f96f955404fb53f37799eadf7ca38cedee64fe952ed1145b458685f0aa08349a3081bfae2042b1362ec71e2a2ecf21c77ffd7d2327d7e74ab9f58ed4d38d143b0098b85eaf4627ba11b447300f5555da2f635141de478b4440638a34d687a133c22f067e0abc0aa886dbc78e0d7dadbfd26069c642084f5a24f5f2f1838ed0d664a11ffa5778c7aa0ceeff9dc7ec4c42fa21680a06e2a8fd27200faf87f1e10bea6dfb1848e25a1e695287489b880e84038aec3728a732a278bcd3ca69102a8eecd056013c05a73c36a61133ca16aab155438251ada916c1896aaae72a1638ed98018b97ef8dd81cbd0f8f70e7dc4dd02d86585af642e2e114d540e375ed701badb8e5aa01d19bd3be2a467d09f3ebfc95fb2a75a7fc445bb0ad83d12c024077f82c5c9d35497e15fbc0aa09d96ec9e6bcdeba6ea1d0eb9a016542717dad6219c6455ddfe9bb9b41dfe384ff7f8dab303e13f28ae09b31f71be1aa878193f73d539e714d6c8975b280f265a618aed2f8426fe369d505f65fed9f981baf653d70433026ae8793b20c9151f8f0a61add90ca6962ec561eb64ca256926880eb2e99169f2de80c8ce41f2e3af5f434136f117fff3689de3bbab838d0028eefbcbb0a6ce5bfbab5fb8350d7a5be7bdc87bbe5a8fdad97f2ed6c7a80bdfbd5fca490636433a8edec834614a4ec4644d2684f10e11559081ddc495c1835dad52373a5f9d5bbb913faf7f00d0f1dc194b689fd9b4a317f619915f0583a236e76cc8967374ba2ef2dcf71882154619a29cd8f1b50ae4d17463543ba530f8942d007bb903459d90925347cad35f4f8c3c82df8597caebbe4c9746e77a0f77953f154a7826aa09c45005a4324a89f65d3210ee4b924f1b400dac99502f279437a9bd744693b2463aefb3440a1b6733b8d0db51e3bedd06a14f39f532a5bfc1583886f1e534db90a905cf1e7303c89b50f1fc58e13c1f921bd6cf923f33a6fb29b7b250ddeabcf1a6d7f930b58771ceaf6b967f01f0c9263f973c59d18396d5c050daf3801d4cdf6f49c4b15729ce4c00e266514f9e11d4ee191dd8ead21896c82ab24bcba38108fbaf1d191aa23028cf954d6b123af4923149b25da6c5175f4a9d98b1e43110e18d794bb419ea82e0cb932c5e32a26931bc5040c01e6f4c83f580624748b5640ad6b5cc3a1b7578a34803ad7cfbb44869ad6e0c34978bee7eae80d0b450619fd464b4b25ed9baea1b40f63047d44743c7aa890e412e15927be8929d6d05d324ec7ca9a08a6f3441841c2cd42d36abb74b8b561d82462cc62bb3a18e426b2138e8cc5660982bdcf4cf0dfcfb4c16cf966177cfeac4d535a5228341832effaa06be5fe94d6f50e835a95dff4f4dcf017632766d5708456b2fb18c23d3db1188ea09bdd2bca8f396e5a2184ebf607780e7be93b24791876f6dbc9815b498da336d8092f674e6b383849b29a168e7c2a9c18bd88eb820b5e4979299d4280fc61d79df31bdc785ae26004062e77befdab2de225d130bf2c4f17d4a4961c0f79854fa9949d2dfe5ee52d5d03af7b0ce4d5bf0d167a09f64d09142d7850f55d22ffd07b5c02fab6eba3dc8269054112539a094d74cc3d5fdcf1cf700e559eadef205f7bdb5506299d2da53ab15af263744032680a3a80a78e0a7c2334acdabe66236c9a6d6414ad47d211efbdac60765430288e8ea12d99143e8c246734583e9c07e17476d1922d18c762b7c1422da7582d048e60ed9bbc649c6f53b32189bc159ce0411415cd368cd226818153d90a9931ce18da8b128230e4608b5c2790bf7f05c44e93c25cb7b8ea41d38c6a19bd71619f862fc698da7609112c6e4363d1c820376c8ea4cbd99fa40932f4560204af91da849f470463672623ace8bc453c765e5ee90cac47c43a04df8cef5c86b97acf99bf2508d99007072f9af075c2209adb4e5b60543c6aeb8d3558c0f6b10764029e2cdf81f4a07b2e202e1d12bbbc15e23be45d1e240e6150e5c2d58c15abb536b8b6df86e71c297d914c36af444d3d592f6f816a50b43340bc643e03e4464511436f69bca169e3a8ce063f53f5e3dd26c4dd4dc6b1dbef798f9a7a952044a30f607c2b7878d242f9062ec007b417dfcb0f27f1efa08a79615ffa79f424d9bd2b73433b4da4dbe2351ebfeb1289a59b35c919d6d863f311de39c48416f041bdf9fa11235fc13e302a82d3333e5e6e7c4b2646c2c801cb41a5fd70ae7bb9e519207f4e1153d119f3695309e96d0c5d7c65c4df1a25df7137cc722ed660cc3b4ce05be8eb6a82f8add7fda859c89f81c94374ab65ca3ded35015bed4b9bfa7b67b79f85ac112656f8d6cda8227c3e942b850c1a458a8789108ad0394c5f809ab05090bf5b3d036a05f07172d383d6771d6d7f10957595f78888cbd088da2b2b7e4ffb8c8ddfe626b7076e6f200000000000000000000000000000000000000000a1212191d23";
const std::string KAT_PUBKEY =
  "0101000020000000539a0673ce6b6f759cc093f790c488c98937bebe9b82a1d0c1e521b65502088ba0070000d1d5abdd90626d8ad8703b2fa94009acdde3b126d417f416dcf3d614da5a7194504c786f32dbcb76f24795f19ac7a78ea475eb5bd10032c598cf543e69271b2dc177d64962a7275ca11260e8038e1d290b69a2fe83f15f7773b9799767e0dadde5a4ee3b0a4525f34996faf7922d333ea7d028c741bf1fdcc00d7fc864a70551cd533eb715c400d1544e97e490c6bba8a91d63aac5e94340f213c5b2dfdd032b852a3069c02122e6d4be9a425cb36d80f5cba33818d4a79961be66074e9954ce5494493f6f3224f2f58b3f0d2dd6e9bf12e20ceb2ca82354f4483a144fe33d07af629542a538e0fe16855637c135df80f11514003c683b1bf04e82fc7dcd1ea6493b48a39894f95f9a0065a351e3f36e4ffc66dcb08f8dbf7da51cb5db83effd9666a1faea2fff632655a932fcc51d71a8074c68dde3701986df42097fcff148ea436552e95de6045c00aba901503c71002cd8db790eb0fd6b16243ead02dd073f07d74863ef287a1d09cc827b78c5c8a81f432e0007ab39f5bee5f8b2188fc4e6d254ab26d557e32ded1e1eba101bf17f7228d51e94f3f215e0234b42b1eed23bc938607141f91e01418eccafa3fb4b1d3e7916edebef4f8d4bb04ec5e06f0e260834e86a066bd3561b402a2278e43fe8f7d3d1157c481941ce00af11bacb1ace2d3a638a0e1b947948ca14f90b072ea0c0b1e93447af9f7f5f44061a654fac1f9c100fea340f56b81abb68dcfacc438cdadaeb9bca42a3294eb0151200cb4392fdb6ed177fa46ca41baf822e26168e8176cc9beb2a991f9b9afdefe7ea60aa50baab5e61af70a873d67b30ca0292353833f57de20254446f83cc1e721ed1b677ce63a3cc1427d4240d11150b87e9ed5db3458af732a9b1f94bfb7260f74546f77d4deb3e3b60ae4fe296ae1c2e1ada7a93481cd286ea3cb9586bd68bd93b803020bfbecf155b80190e539e7cbca37b95d724ac99fa715d95a3d31e954fb53aa5c797066c2c00fc26d0bce9fd8b0920d4a87a92aab825972afd83e43f3f21cae82ebb3e449586f854f29950c2ac1fc5361e00d28844590116b15c51da46834710084e98c316ccf1e242aa1a1c9e3b3a2e14ceda2cf94d3990f378ef1e8fcd6bfa8178f96fb740d8a69bef620601a1d5c0a2402f794acc533230060ae64dcadb6f68a9c8911170e653d6a80b68a14011d40cb4ad0a085c0d680bc1cc14217b17d788898e5221e2f16b1588bfde5af95c7f3c83c73d603e92cf6407acce99be24452f3c7b6dbbdb90f32be7b2ae68e03cae31ec81d60fef0f944858f61c5ef0f638eac7d1e315f626021f6184ae4d9e307864ae45dc2cc90a06d0fab9b25a5cde48e2e9ed5f52df547b419e8d35e4697b71dda20cf0976efe5551086b756061e82e8bb3e4b7ad2788f3bcc1fa49044edc6085c35c84b66b1db9d3062e4a7c5de8ed5e7acf2a2d8a0f1c12e8b35d244f6cade3b0c7b385494276a2d744cd3f72028a17d75559eed2a4eaca2a2ad83d4110183ee8ebb495b0300c3486bf6db70cfe7dbf96337b96cf51d44c51dd72404e624d94098991f2d9521f47783b3a0e8592d24513fbe3413357bda7dead7b940156d632832a3717144a88d76938fdebdc6cb914ad2eead0b97c6b0851ce43b848881ff567f59f2c759c21f564a64aa36d087b5a722de8720b9660369f37c6b675c9797acd1765dec81b3a4c0ccd38947853893c0f1381e7b05409312151fdb4526773863e674de7a9d68297f54596406b593152380466f03fae97efedf9bcb512a8174c32f297fd6f2eac8101e8404af7a5ce9a1fe948dcdbc45d5441f2357f6b0d204cfeded63e615b01ade8bb5880773436029f2320acabde401f4ae26435243d6b02c2cbb7a41de95e68fc57ee10b5889575482d299d8b98118349f480351c3bec268f79d2140812545803f57d9991e094641d9c6c90428cce7020d437216ef07c6790cd67d2f3aac2fa3adb95bc260d3981ee40a3faae621ec7e1da4d5434989920cd9b942c6925bd4ae17d7b7d80b7ee91faab78dc97d39a94889a84c7eb8f89be99523208cc29bd609e628ae1ba87d4ad1cf2ae5ff506b1db5875a0ceaee60544f540c39abe5c975b225ac450dd63018892d5cbdba8b8ba8867207fe2f9f8f84bd057e127823f096d6fa63b3eae86a76b7c3c474ff9e7c6e3aae52c583024b4a894cfedb2326d19f5b8d48abc70c66be577c226ae63326caaccbc18ee8df9e4317fa00194c99238040889402ac209b60235e466ac3a194b37a9df169380a811a0b81a54080f71c8adcd78715e15f6d75f190d5614db4e802486e45aff7b114e6ccddfefad73ba0e53d59384a8c17d59a0a4b86501a96d0e07cc460051003032293c522e6e476efe70e24c7f42dfcea8399e72cb03ddcc6579a8469c1ff8fea3c614825e473f362317dcdc8f21e8b609e0e5f19bee8ac7c27cd10ad04c1a8ee07d70d727abd67cba4698dc46b3f66aa9d04a9faeaca6876fae5c2ec28a5d99d39f4249bd72cdc8dea5952c71c4399e461f8208e8b720ce8a1ac6ca01f71cacae8e732ec6c08d8a3a25ecdb618ea29f29de6665627e65e99857f496725a8e570d8d89f060fc910d692f4b8850b11d4668a9a79ea156ed89842d6a79e84cfc5003247b29abeb15df8909db7bb4711c1cd109c35cae54f7d3c5df78a3ea227e12da91612c9bc5f3b94570ea387f390a3611a84a8dfd698ed909b0dbea97ff5bf43f75255ee1fb88f9e69ccb543018ccc4";

// Verify the pinned vector with one (pair_pid, pair_pubkey) pair, a chosen root and a
// chosen cb-readable flag. Every buffer lives for the synchronous FFI call.
uint8_t run_verify(const std::vector<uint8_t>& root, uint8_t cb_readable,
  const std::vector<uint8_t>& pair_pid, const std::vector<uint8_t>& pair_pubkey)
{
  const std::vector<uint8_t> headers = from_hex(KAT_HEADERS);
  const std::vector<uint8_t> witness = from_hex(KAT_WITNESS);
  const std::vector<uint8_t> cbkey = from_hex(KAT_CBKEY);

  shekyl_archival_pid_pubkey pair{};
  std::memcpy(pair.p_id, pair_pid.data(), 32);
  pair.pubkey_ptr = pair_pubkey.empty() ? nullptr : pair_pubkey.data();
  pair.pubkey_len = pair_pubkey.size();

  const std::vector<uint8_t> prev_block_hash = from_hex(KAT_PREV_BLOCK_HASH);
  shekyl_archival_attestation_verify_ctx ctx{};
  std::memcpy(ctx.attestation_root, root.data(), 32);
  std::memcpy(ctx.cb_out_key, cbkey.data(), 32);
  std::memcpy(ctx.prev_block_hash, prev_block_hash.data(), 32);
  ctx.cb_out_key_readable = cb_readable;
  ctx.headers_readable = 1;
  ctx.headers_ptr = headers.data();
  ctx.headers_len = headers.size();
  ctx.pairs_ptr = &pair;
  ctx.pairs_len = 1;
  return shekyl_archival_verify_attestation(witness.data(), witness.size(), &ctx);
}
}  // namespace

// The layout agrees end to end: the frozen vector, marshaled through the C structs, verifies OK.
TEST(archival_attestation_verify, pinned_valid_vector_verifies_ok)
{
  EXPECT_EQ(run_verify(from_hex(KAT_ROOT), 1, from_hex(KAT_P_ID), from_hex(KAT_PUBKEY)),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
}

// attestation_root field offset: flip one byte -> ROOT_MISMATCH.
TEST(archival_attestation_verify, flipped_root_is_root_mismatch)
{
  std::vector<uint8_t> root = from_hex(KAT_ROOT);
  root[0] ^= 0x01;
  EXPECT_EQ(run_verify(root, 1, from_hex(KAT_P_ID), from_hex(KAT_PUBKEY)),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ROOT_MISMATCH);
}

// pubkey_len == 0 is the bond-absent marker (a missing LMDB bond), not a bad signature.
TEST(archival_attestation_verify, absent_bond_is_bond_absent)
{
  EXPECT_EQ(run_verify(from_hex(KAT_ROOT), 1, from_hex(KAT_P_ID), std::vector<uint8_t>{}),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_BOND_ABSENT);
}

// pair p_id offset + coverage: a pair that names no pass record (and a pass record with no
// pair) is a set mismatch, the loud verdict that makes the pairs-not-positional design safe.
TEST(archival_attestation_verify, wrong_pair_pid_is_set_mismatch)
{
  const std::vector<uint8_t> wrong_pid(32, 0xAB);
  EXPECT_EQ(run_verify(from_hex(KAT_ROOT), 1, wrong_pid, from_hex(KAT_PUBKEY)),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH);
}

// cb_out_key_readable flag: 0 means C++ could not read the coinbase key -> the verify refuses
// rather than binding the nonce to garbage.
TEST(archival_attestation_verify, unreadable_cbkey_is_cbkey_unreadable)
{
  EXPECT_EQ(run_verify(from_hex(KAT_ROOT), 0, from_hex(KAT_P_ID), from_hex(KAT_PUBKEY)),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CBKEY_UNREADABLE);
}

// headers_readable flag offset: 0 means C++ could not parse the coinbase tx_extra -> the verify
// refuses rather than misreading a malformed extra as the committed empty attestation set.
TEST(archival_attestation_verify, unreadable_headers_is_headers_unreadable)
{
  uint8_t empty_root[32];
  ASSERT_TRUE(shekyl_attestation_root_empty(empty_root));

  shekyl_archival_attestation_verify_ctx ctx{};
  std::memcpy(ctx.attestation_root, empty_root, 32);
  // Non-zero anchor: all-zeros is the unpopulated-field sentinel, so leaving it would make
  // these arms fail on ERR_PREVHASH_UNPOPULATED instead of the verdict each one pins.
  std::memset(ctx.prev_block_hash, 0x07, 32);
  ctx.cb_out_key_readable = 1;
  ctx.headers_readable = 0;
  EXPECT_EQ(shekyl_archival_verify_attestation(nullptr, 0, &ctx),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_HEADERS_UNREADABLE);
}

// The empty (pre-cutover) shape across the FFI: the C++ empty root (shekyl_attestation_root_empty)
// agrees with the Rust verify's recompute over zero records -> OK; a non-empty root -> reject.
TEST(archival_attestation_verify, empty_shape_across_ffi)
{
  uint8_t empty_root[32];
  ASSERT_TRUE(shekyl_attestation_root_empty(empty_root));

  shekyl_archival_attestation_verify_ctx ctx{};
  std::memcpy(ctx.attestation_root, empty_root, 32);
  // Non-zero anchor: all-zeros is the unpopulated-field sentinel, so leaving it would make
  // these arms fail on ERR_PREVHASH_UNPOPULATED instead of the verdict each one pins.
  std::memset(ctx.prev_block_hash, 0x07, 32);
  ctx.cb_out_key_readable = 1;  // no records -> the key value is unused, but the flag must be set
  ctx.headers_readable = 1;     // parsed extra, no attestation tag -> the committed empty set
  ctx.headers_ptr = nullptr;
  ctx.headers_len = 0;
  ctx.pairs_ptr = nullptr;
  ctx.pairs_len = 0;
  EXPECT_EQ(shekyl_archival_verify_attestation(nullptr, 0, &ctx),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);

  ctx.attestation_root[0] ^= 0x01;
  EXPECT_EQ(shekyl_archival_verify_attestation(nullptr, 0, &ctx),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ROOT_MISMATCH);
}

// Step 1 marshaling: C++ hands the same header blob to shekyl_archival_attestation_pass_p_ids and
// gets back exactly the pinned pass p_id the ctx above pairs against.
TEST(archival_attestation_verify, step1_names_the_pinned_pass_pid)
{
  const std::vector<uint8_t> headers = from_hex(KAT_HEADERS);
  uint8_t out[config::ARCHIVAL_MAX_ATTESTATION_RECORDS][32];
  size_t n = 0;
  const uint8_t code = shekyl_archival_attestation_pass_p_ids(
    headers.data(), headers.size(), out, config::ARCHIVAL_MAX_ATTESTATION_RECORDS, &n);
  EXPECT_EQ(code, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
  ASSERT_EQ(n, 1u);
  const std::vector<uint8_t> p_id = from_hex(KAT_P_ID);
  EXPECT_EQ(std::memcmp(out[0], p_id.data(), 32), 0);
}
