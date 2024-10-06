

void test_single_message_type_unreliable()
{
    SingleTestMessageFactory messageFactory(GetDefaultAllocator());

    double time = 100.0;

    ConnectionConfig connectionConfig;
    connectionConfig.numChannels = 1;
    connectionConfig.channel[0].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

    Connection sender(GetDefaultAllocator(), messageFactory, connectionConfig, time);
    Connection receiver(GetDefaultAllocator(), messageFactory, connectionConfig, time);

    const int SenderPort = 10000;
    const int ReceiverPort = 10001;

    Address senderAddress("::1", SenderPort);
    Address receiverAddress("::1", ReceiverPort);

    const int NumIterations = 256;

    const int NumMessagesSent = 16;

    for (int j = 0; j < NumMessagesSent; ++j)
    {
        TestMessage * message = (TestMessage*) messageFactory.CreateMessage(SINGLE_TEST_MESSAGE);
        check(message);
        message->sequence = j;
        sender.SendMessage(0, message);
    }

    int numMessagesReceived = 0;

    uint16_t senderSequence = 0;
    uint16_t receiverSequence = 0;

    for (int i = 0; i < NumIterations; ++i)
    {
        pump_connection_update(connectionConfig, time, sender, receiver, senderSequence, receiverSequence, 0.1f, 0);

        while (true)
        {
            Message * message = receiver.ReceiveMessage(0);
            if (!message)
                break;

            check(message->GetType() == SINGLE_TEST_MESSAGE);

            TestMessage * testMessage = (TestMessage*) message;

            check(testMessage->sequence == uint16_t(numMessagesReceived));

            ++numMessagesReceived;

            messageFactory.ReleaseMessage(message);
        }

        if (numMessagesReceived == NumMessagesSent)
            break;
    }

    check(numMessagesReceived == NumMessagesSent);
}


void send_client_to_server_messages_sample((Client & client, int numMessagesToSend, int channelIndex = 0)
{
    for (int i = 0; i < numMessagesToSend; ++i)
    {
        if (!client.CanSendMessage(channelIndex))
            break;

        TestMessage * message = (TestMessage*) client.CreateMessage(TEST_MESSAGE);
        check(message);
        message->sequence = i;
        client.SendMessage(channelIndex, message);
    }
}

void send_server_to_client_messages_sample((Server & server, int clientIndex, int numMessagesToSend, int channelIndex = 0)
{
    for (int i = 0; i < numMessagesToSend; ++i)
    {
        if (!server.CanSendMessage(clientIndex, channelIndex))
            break;

        TestMessage * message = (TestMessage*) server.CreateMessage(clientIndex, TEST_MESSAGE);
        check(message);
        message->sequence = i;
        server.SendMessage(clientIndex, channelIndex, message);
    }
}

void process_server_to_client_messages_sample((Client & client, int & numMessagesReceivedFromServer)
{
    while (true)
    {
        Message * message = client.ReceiveMessage(0);

        if (!message)
            break;

        switch (message->GetType())
        {
            case TEST_MESSAGE:
            {
                ++numMessagesReceivedFromServer;
            }
            break;
        }

        client.ReleaseMessage(message);
    }
}

void process_client_to_server_messages_sample((Server & server, int clientIndex, int & numMessagesReceivedFromClient)
{
    while (true)
    {
        Message * message = server.ReceiveMessage(clientIndex, 0);

        if (!message)
            break;

        switch (message->GetType())
        {
            case TEST_MESSAGE:
            {
                check(!message->IsBlockMessage());
                ++numMessagesReceivedFromClient;
            }
            break;
        }

        server.ReleaseMessage(clientIndex, message);
    }
}

void test_client_server_messages_network_sim_leak()
{
    const uint64_t clientId = 1;

    Address clientAddress("0.0.0.0", ClientPort);
    Address serverAddress("127.0.0.1", ServerPort);

    double time = 100.0;

    ClientServerConfig config;
    config.networkSimulator = true;
    config.channel[0].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

    Client client(GetDefaultAllocator(), clientAddress, config, adapter, time);

    uint8_t privateKey[KeyBytes];
    memset(privateKey, 0, KeyBytes);

    Server server(GetDefaultAllocator(), privateKey, serverAddress, config, adapter, time);

    server.Start(MaxClients);

    server.SetLatency(500);
    server.SetJitter(100);
    server.SetPacketLoss(5);
    server.SetDuplicates(5);

    for (int iteration = 0; iteration < 2; ++iteration)
    {
        client.InsecureConnect(privateKey, clientId, serverAddress);

        client.SetLatency(500);
        client.SetJitter(100);
        client.SetPacketLoss(5);
        client.SetDuplicates(5);

        const int NumIterations = 10000;

        for (int i = 0; i < NumIterations; ++i)
        {
            Client * clients[] = { &client };
            Server * servers[] = { &server };

            PumpClientServerUpdate(time, clients, 1, servers, 1);

            if (client.ConnectionFailed())
                break;

            if (client.IsConnected() && server.GetNumConnectedClients() == 1)
                break;
        }

        check(!client.IsConnecting());
        check(client.IsConnected());
        check(server.GetNumConnectedClients() == 1);
        check(client.GetClientIndex() == 0);
        check(server.IsClientConnected(0));

        const int NumMessagesSent = 2000;

        send_client_to_server_messages_sample((client, NumMessagesSent);

        send_server_to_client_messages_sample((server, client.GetClientIndex(), NumMessagesSent);

        int numMessagesReceivedFromClient = 0;
        int numMessagesReceivedFromServer = 0;

        for (int i = 0; i < 100; ++i)
        {
            if (!client.IsConnected())
                break;

            Client * clients[] = { &client };
            Server * servers[] = { &server };

            PumpClientServerUpdate(time, clients, 1, servers, 1);

            process_server_to_client_messages_sample((client, numMessagesReceivedFromServer);
            process_client_to_server_messages_sample((server, client.GetClientIndex(), numMessagesReceivedFromClient);
        }

        check(client.IsConnected());
        check(server.IsClientConnected(client.GetClientIndex()));

        client.Disconnect();

        for (int i = 0; i < NumIterations; ++i)
        {
            Client * clients[] = { &client };
            Server * servers[] = { &server };

            PumpClientServerUpdate(time, clients, 1, servers, 1);

            if (!client.IsConnected() && server.GetNumConnectedClients() == 0)
                break;
        }

        check(!client.IsConnected() && server.GetNumConnectedClients() == 0);
    }

    server.Stop();
}
