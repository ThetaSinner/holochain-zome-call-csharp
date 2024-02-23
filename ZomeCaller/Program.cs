using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Text;
using MessagePack;
using Sodium;

namespace ZomeCaller;

internal class Program
{
    static async Task Main(string[] args)
    {
        var client = await Client.create();
        
        var signingKeyPair = client.generateSigningKeyPair();

        PrintByteArray("signing key", signingKeyPair.SigningKey);
        PrintByteArray("public key", signingKeyPair.KeyPair.PublicKey);

        var testDnaHashStr = "uhC0kDNGYhRcOujFJDf-B39nK-veqq-I2FYyBWupaWQ91FVToz4xS";
        byte[] testDnaHash = FromBase64UrlSafe(testDnaHashStr[1..]);
        PrintByteArray("dna hash", testDnaHash);

        var testAgentKeyStr = "uhCAk5ebLEPT4iv4m4A6dCAG1Mkzd2KVHZ7DZVd3yAIBfTuzGNsTs";
        byte[] testAgentKey = FromBase64UrlSafe(testAgentKeyStr[1..]);
        PrintByteArray("agent key", testAgentKey);

        var capSecret = client.createRandomCapSecret();
        PrintByteArray("cap secret", capSecret);

        var nonce = client.createRandomNonce();
        PrintByteArray("nonce", nonce);

        var expires_at = (DateTimeOffset.Now.ToUnixTimeMilliseconds() + 5 * 60 * 1000) * 1000;
        Console.WriteLine("Expires at: " + expires_at);

        var call = new ZomeCallUnsigned {
            provenance = signingKeyPair.SigningKey,
            cell_id_dna_hash = testDnaHash,
            cell_id_agent_pub_key = testAgentKey,
            zome_name = "drone_swarm",
            fn_name = "get_current_lobbies",
            cap_secret = capSecret,
            payload = Array.Empty<byte>(),
            nonce = nonce,
            expires_at = expires_at,
        };

        var dataToSign = new byte[32];
        try
        {
            HolochainSerialisationWrapper.call_get_data_to_sign(dataToSign, call);
        } catch (Exception e)
        {
            Console.WriteLine("Failed to get: " + e.ToString());
        }

        PrintByteArray("data to sign", dataToSign);

        var capAccess = new CapAccess { Assigned = new CapAccessAssigned { CapSecret = capSecret, Assignees = [testAgentKey] } };

        var zomeCallCapGrant = new ZomeCallCapGrant { Tag = "zome-call-signing-key", Access = capAccess };

        var grantPayload = new GrantZomeCallCapabilityPayload([testDnaHash, testAgentKey], zomeCallCapGrant);

        var adminRequest = new AdminRequest("grant_zome_call_capability", grantPayload);
        var messageInner = MessagePackSerializer.Serialize(adminRequest);

        var request = new WireMessage(1, "request", messageInner);

        if (client.ClientWs.State != WebSocketState.Open)
        {
            Console.WriteLine("Websocket is not open");
        }

        try
        {
            var response = await client.Send(request);
            
            var adminResponse = MessagePackSerializer.Deserialize<AdminResponse>(response.Data);
            if (adminResponse.Type != "zome_call_capability_granted")
            {
                throw new Exception("Got an error, wanted zome call cap granted");
            }

            Console.WriteLine("Capability granted");
        } catch (Exception e)
        {
            Console.WriteLine("Failed to grant cap: " + e.ToString());
        }

        await client.ClientWs.CloseAsync(WebSocketCloseStatus.NormalClosure, "finished", CancellationToken.None);
        client.Handle?.Join();
    }

    public static void PrintByteArray(string msg, byte[] bytes)
    {
        var sb = new StringBuilder(msg);
        sb.Append(": new byte[] { ");
        foreach (var b in bytes)
        {
            sb.Append(b + ", ");
        }
        sb.Append("}");
        Console.WriteLine(sb.ToString());
    }

    public static byte[] FromBase64UrlSafe(string input)
    {
        string incoming = input.Replace('_', '/').Replace('-', '+');
        switch (input.Length % 4)
        {
            case 2: incoming += "=="; break;
            case 3: incoming += "="; break;
        }
        return Convert.FromBase64String(incoming);
    }
}

internal class Client
{
    public ClientWebSocket ClientWs { get; }

    public ConcurrentDictionary<int, WireMessage> Responses { get; } = new ConcurrentDictionary<int, WireMessage>();

    public ConcurrentDictionary<int, TaskCompletionSource> Requests { get; } = new ConcurrentDictionary<int, TaskCompletionSource>();

    public Thread? Handle { get; private set; }

    private Client(ClientWebSocket clientWs)
    {
        ClientWs = clientWs;
    }

    internal static async Task<Client> create()
    {
        Uri uri = new("ws://localhost:8888");

        ClientWebSocket ws = new();
        await ws.ConnectAsync(uri, CancellationToken.None);
        Console.WriteLine(ws.State);

        var client = new Client(ws);
        Thread t = new Thread(new ThreadStart(client.RunReceiver));
        t.Start();
        client.Handle = t;

        return client;
    }

    internal async Task<WireMessage> Send(WireMessage msg)
    {
        var tcs = new TaskCompletionSource();
        Requests.TryAdd(msg.Id, tcs);

        var request = MessagePackSerializer.Serialize(msg);
        await ClientWs.SendAsync(request, WebSocketMessageType.Binary, true, CancellationToken.None);

        await tcs.Task;
        Responses.Remove(msg.Id, out var response);
        Requests.Remove(msg.Id, out var _);

        if (response == null)
        {
            throw new Exception("Missing response, broken mechanism?");
        }

        return response;
    }

    internal async Task auth_creds()
    {

    }

    // TODO private
    internal SigningKeyPair generateSigningKeyPair()
    {
        var keyPair = Sodium.PublicKeyAuth.GenerateKeyPair();

        var signingKey = new byte[39];

        Buffer.BlockCopy(new byte[3] { 132, 32, 36 }, 0, signingKey, 0, 3);
        Buffer.BlockCopy(keyPair.PublicKey, 0, signingKey, 3, 32);
        Buffer.BlockCopy(new byte[4] { 0, 0, 0, 0 }, 0, signingKey, 35, 4);

        return new SigningKeyPair(keyPair, signingKey);
    }

    internal byte[] createRandomCapSecret()
    {
        return SodiumCore.GetRandomBytes(64);
    }

    internal byte[] createRandomNonce()
    {
        return SodiumCore.GetRandomBytes(32);
    }

    internal void RunReceiver()
    {
        Task.Run(async () =>
        {
            Console.WriteLine("Background receiver started");
            ArraySegment<Byte> buffer = new ArraySegment<byte>(new Byte[8192]);
            while (ClientWs.State == WebSocketState.Open)
            {
                try
                {
                    var result = await ClientWs.ReceiveAsync(buffer, CancellationToken.None);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await ClientWs.CloseAsync(WebSocketCloseStatus.NormalClosure, string.Empty, CancellationToken.None);
                    }
                    else
                    {
                        var content = new byte[result.Count];
                        Buffer.BlockCopy(buffer.Array, 0, content, 0, result.Count);
                        var m = MessagePackSerializer.Deserialize<WireMessage>(content);
                        Console.WriteLine(String.Format("Got a message: {0}, {1}", m.Id, m.Type));
                        Program.PrintByteArray("response", m.Data);

                        Requests.TryGetValue(m.Id, out var tcs);
                        if (tcs == null)
                        {
                            throw new Exception("Missing response handler, broken mechanism?");
                        }

                        Responses.TryAdd(m.Id, m);
                        tcs.SetResult();
                    }
                } catch (Exception ex)
                {
                    Console.WriteLine("WebSocket failed: " + ex.ToString());
                }
            }

            Console.WriteLine("Background receiver finished");
            Console.WriteLine(ClientWs.CloseStatus);
            Console.WriteLine(ClientWs.CloseStatusDescription);
            Console.WriteLine(ClientWs.State);
        }).Wait();
    }
}

internal class SigningKeyPair
{
    public KeyPair KeyPair { get; }
    public byte[] SigningKey { get; }

    public SigningKeyPair(KeyPair keyPair, byte[] signingKey)
    {
        KeyPair = keyPair;
        SigningKey = signingKey;
    }
}

[MessagePackObject]
public class GrantZomeCallCapabilityPayload
{
    [Key("cell_id")]
    public byte[][] CellId { get; set; }

    [Key("cap_grant")]
    public ZomeCallCapGrant CapGrant { get; set; }


    public GrantZomeCallCapabilityPayload(byte[][] cellId, ZomeCallCapGrant capGrant)
    {
        CellId = cellId;
        CapGrant = capGrant;
    }
}

[MessagePackObject]
public class ZomeCallCapGrant
{
    [Key("tag")]
    public string Tag { get; set; }

    [Key("access")]
    public CapAccess Access { get; set; }

    [Key("functions")]
    public GrantedFunctionsAll GrantedFunctions = new GrantedFunctionsAll();
}

[MessagePackObject]
public class CapAccess
{
    [Key("Assigned")]
    public CapAccessAssigned Assigned { get; set; }
}

[MessagePackObject]
public class CapAccessAssigned
{
    [Key("secret")]
    public byte[] CapSecret { get; set; }

    [Key("assignees")]
    public byte[][] Assignees { get; set; }
}

public enum GrantedFunctionsType
{
    All,
    Listed
}

[MessagePackObject]
public class GrantedFunctionsAll
{
    [Key("All")]
    public string? All = null;
}

[MessagePackObject]
public class AdminRequest
{
    [Key("type")]
    public string Tag { get; set; }

    [Key("data")]
    public GrantZomeCallCapabilityPayload Data { get; set; }

    public AdminRequest(string tag, GrantZomeCallCapabilityPayload data)
    {
        Tag = tag;
        Data = data;
    }
}

[MessagePackObject]
public class WireMessage
{
    [Key("id")]
    public int Id { get; set; }

    [Key("type")]
    public string Type { get; set; }

    [Key("data")]
    public byte[] Data { get; set; }

    public WireMessage(int id, string type, byte[] data)
    {
        Id = id;
        Type = type;
        Data = data;
    }
}

[MessagePackObject]
public class AdminResponse
{
    [Key("type")]
    public string Type { get; set; }
}
