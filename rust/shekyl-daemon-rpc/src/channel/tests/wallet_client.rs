use super::{client, code, CeilingWord, Duration, Served, StaticKeypair, Value, HOST};

/// Drive the actual wallet connection against a responding daemon. The key
/// and bundle come from disk, as they do at the wallet's first remote use.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_enrollment_wrong_bundle_and_revocation() {
    let served = Served::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    // The owner rendezvous and the service record share a file name on
    // Windows (`shekyl-<name>`). They live in different directories, which
    // is also how a machine publishes them.
    let service_dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("client.key");
    let bundle_file = dir.path().join("bundle");
    std::fs::write(
        &bundle_file,
        client::bundle_text(&served.channel.bundle_show().bundle.0),
    )
    .unwrap();
    let node = client::RemoteNode {
        leg: client::Leg::ip(served.addr, None),
        bundle_file,
    };
    let open = || {
        client::account_target(
            shekyl_network::Network::Regtest,
            node.leg.clone(),
            node.bundle().unwrap(),
            Some(&key_file),
        )
    };
    let first = open().err().expect("first use creates a key and stops");
    let key = client::read_client_key(&key_file).unwrap().unwrap();
    let fingerprint = *key.public().fingerprint().as_bytes();
    assert_eq!(first, client::ChannelFault::NotEnrolled { fingerprint });
    let network = shekyl_network::Network::Regtest;
    let instance = shekyl_rpc_rendezvous::Instance::Default;
    let local = shekyl_rpc_transport::local::LocalTarget::test_override(
        network,
        &instance,
        Some(dir.path()),
        Some(service_dir.path()),
    );
    let service = shekyl_rpc_rendezvous::ServiceRecord {
        channel: Some(shekyl_rpc_rendezvous::ServiceChannel {
            address: served.addr,
            bundle: served.channel.bundle_show().bundle.0,
        }),
        view: None,
    };
    std::fs::write(
        shekyl_rpc_rendezvous::service_record_path(
            service_dir.path(),
            &network.network_id(),
            &instance,
        ),
        service.bytes(),
    )
    .unwrap();
    let local_wallet = || {
        client::WalletChannel::new(
            shekyl_rpc_transport::service_channel(&local, network, Some(&key_file))
                .unwrap()
                .expect("the service published a channel"),
            Duration::from_secs(5),
        )
    };
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"version","params":{}}"#;
    let connect = || client::WalletChannel::new(open().unwrap(), Duration::from_secs(5));
    assert_eq!(
        connect().post("json_rpc", body.to_vec()).await.unwrap_err(),
        first
    );
    assert_eq!(
        local_wallet()
            .post("json_rpc", body.to_vec())
            .await
            .unwrap_err(),
        first
    );
    served.enroll(&key, &[CeilingWord::Wallet]);
    let wallet = connect();
    let reply = wallet.post("json_rpc", body.to_vec()).await.unwrap();
    assert_eq!(
        local_wallet()
            .post("json_rpc", body.to_vec())
            .await
            .unwrap(),
        reply
    );
    // The fixture deliberately has no node handles. Version reaches the handler
    // and returns that application's typed refusal over the admitted channel.
    let version: Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(code(&version), Some("daemon.unready"), "{version}");
    served.channel.client_remove(HOST, fingerprint).unwrap();
    assert_eq!(
        wallet.post("json_rpc", body.to_vec()).await.unwrap_err(),
        client::ChannelFault::Revoked { fingerprint }
    );
    let other = StaticKeypair::generate().unwrap();
    std::fs::write(
        &node.bundle_file,
        client::bundle_text(&super::super::bundle(&other)),
    )
    .unwrap();
    let wrong = connect();
    for _ in 0..2 {
        assert!(matches!(
            wrong.post("json_rpc", body.to_vec()).await,
            Err(client::ChannelFault::NotRecognised { .. })
        ));
    }
    // A complete, invalid second message is a different failure than a real
    // daemon closing before it sends its proof.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let answer = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hello = vec![0; shekyl_rpc_channel::handshake::MESSAGE1_LEN];
        stream.read_exact(&mut hello).await.unwrap();
        stream
            .write_all(&vec![0; shekyl_rpc_channel::handshake::MESSAGE2_LEN])
            .await
            .unwrap();
        // Close only after the client has: a close with the client's bytes
        // still unread resets the connection on Windows, and the reset
        // reaches the client before the message it was sent, so the client
        // would report the reset and not this message.
        let mut rest = Vec::new();
        drop(stream.read_to_end(&mut rest).await);
    });
    let target = client::account_target(
        network,
        client::Leg::ip(addr, None),
        node.bundle().unwrap(),
        Some(&key_file),
    )
    .unwrap();
    let wallet = client::WalletChannel::new(target, Duration::from_secs(5));
    for _ in 0..2 {
        assert!(matches!(
            wallet.post("json_rpc", body.to_vec()).await,
            Err(client::ChannelFault::NotTheDaemon { .. })
        ));
    }
    answer.await.unwrap();
    served.stop.send_replace(true);
    served.serving.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_and_console_receive_the_grants_enrolled_on_the_daemon() {
    use shekyl_rpc_grants::Preset;
    let served = Served::start(false).await;
    let key = StaticKeypair::generate().unwrap();
    let fingerprint = *key.public().fingerprint().as_bytes();
    served.enroll(&key, &[CeilingWord::Wallet]);
    let target = client::ChannelTarget::new(
        super::network_id(),
        served.bundle(),
        key,
        client::Leg::ip(served.addr, None),
    );
    let connect_console = || {
        let target = target.clone();
        std::thread::spawn(move || {
            client::ChannelDaemon::connect_enrolled(&target, Duration::from_secs(5))
                .unwrap()
                .granted()
        })
        .join()
        .unwrap()
    };
    assert_eq!(connect_console(), Preset::Wallet.grants());

    let wallet = client::WalletChannel::new(target.clone(), Duration::from_secs(5));
    let mine_stop = br#"{"jsonrpc":"2.0","id":1,"method":"mine_stop","params":{}}"#;
    let reply = wallet.post("json_rpc", mine_stop.to_vec()).await.unwrap();
    assert_eq!(
        code(&serde_json::from_slice(&reply).unwrap()),
        Some("grant.outside")
    );

    served
        .channel
        .client_set(HOST, fingerprint, &[CeilingWord::Admin])
        .unwrap();
    assert_eq!(connect_console(), Preset::Admin.grants());
    let reply = wallet.post("json_rpc", mine_stop.to_vec()).await.unwrap();
    assert_eq!(
        code(&serde_json::from_slice(&reply).unwrap()),
        Some("grant.outside"),
        "a raise applies on the next connection"
    );

    let wallet = client::WalletChannel::new(target, Duration::from_secs(5));
    let reply = wallet.post("json_rpc", mine_stop.to_vec()).await.unwrap();
    assert_eq!(
        code(&serde_json::from_slice(&reply).unwrap()),
        Some("daemon.unready")
    );

    served.stop.send_replace(true);
    served.serving.await.unwrap().unwrap();
}
