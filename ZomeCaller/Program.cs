using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Text;
using MessagePack;
using Sodium;

namespace ZomeCaller;

internal class Program
{
    // Needs to be configured to call your zome and function, currently hard-coded to one of my happs.
    //
    // Expects you to have done a `hc s generate <my-happ.happ>`, followed by an `hc s -f 8888, run`
    // Once running, `hc s -f 8888, call list-apps` to get your agent key and dna hash, then attach an 
    // app websocket port using `hc s -f 8888, call add-app-ws`. Use the agent key, dna hash and app port
    // to update this file.
    static async Task Main(string[] args)
    {
        // Connect to the admin port of Holochain
        var adminClient = await Client.create(8888);
        
        // Create a keypair, extracting the public key into an 'identity' which is in AgentPubKey format
        var signingKeyPair = adminClient.generateSigningKeyPair();

        // The 'identity' to assign the cap grant to
        PrintByteArray("signing key", signingKeyPair.Identity);
        // The public key that should be inside the 'identity' signing key.
        PrintByteArray("public key", signingKeyPair.KeyPair.PublicKey);

        // This is test data retrieved from `hc s -f 8888, call list-apps`
        var testDnaHashStr = "uhC0kDNGYhRcOujFJDf-B39nK-veqq-I2FYyBWupaWQ91FVToz4xS";
        byte[] testDnaHash = FromBase64UrlSafe(testDnaHashStr[1..]);
        PrintByteArray("dna hash", testDnaHash);

        // This is test data retrieved from `hc s -f 8888, call list-apps`
        var testAgentKeyStr = "uhCAkWSFV24oX-iY45knQ-znE7x3navgJEJOh_peaW9s3uPVY3viW";
        byte[] testAgentKey = FromBase64UrlSafe(testAgentKeyStr[1..]);
        PrintByteArray("agent key", testAgentKey);

        // Create a cap secret, this should be kept for the same lifetime as the signingKeyPair
        var capSecret = adminClient.createRandomCapSecret();
        PrintByteArray("cap secret", capSecret);

        // Create a nonce, this should be created for every zome call
        var nonce = adminClient.createRandomNonce();
        PrintByteArray("nonce", nonce);

        // Now +5m in microseconds
        var expires_at = (DateTimeOffset.Now.ToUnixTimeMilliseconds() + 5 * 60 * 1000) * 1000;
        Console.WriteLine("Expires at: " + expires_at);

        // Build a capability access payload, allowing our 'identity' keypair to access all functions
        var capAccess = new CapAccess { Assigned = new CapAccessAssigned { CapSecret = capSecret, Assignees = [signingKeyPair.Identity] } };
        var zomeCallCapGrant = new ZomeCallCapGrant { Tag = "zome-call-signing-key", Access = capAccess };
        var grantPayload = new GrantZomeCallCapabilityPayload([testDnaHash, testAgentKey], zomeCallCapGrant);
        var adminRequest = new AdminRequest("grant_zome_call_capability", grantPayload);
        var messageInner = MessagePackSerializer.Serialize(adminRequest);

        // Dump the capability request for debugging
        var json = MessagePackSerializer.ConvertToJson(messageInner);
        Console.WriteLine(json);

        var request = new WireMessage(1, "request", messageInner);

        try
        {
            // Send the request to create a cap access record for our 'identity'
            var response = await adminClient.Send(request);
            
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

        // Create the unsigned zome call, to sign and then later convert to a real zome call
        var zomeCall = new ZomeCallUnsigned
        {
            provenance = signingKeyPair.Identity,
            cell_id_dna_hash = testDnaHash,
            cell_id_agent_pub_key = testAgentKey,
            zome_name = "drone_swarm",
            fn_name = "get_current_lobbies",
            cap_secret = capSecret,
            payload = [0xc0], // Nil byte because my test zome function happens to have a signature of `zome_fn(_: ()) -> ExternResult<Vec<..>>`. This should be your msgpack encoded payload to your zome
            nonce = nonce,
            expires_at = expires_at,
        };

        var zomeCallDataToSign = new byte[32];
        try
        {
            // Call into the `holochain_zome_types` crate to get a blake2b hash of the zomeCall
            HolochainSerialisationWrapper.call_get_data_to_sign(zomeCallDataToSign, zomeCall);
        }
        catch (Exception e)
        {
            Console.WriteLine("Failed to get data to sign: " + e.ToString());
        }

        // Sign the zome call hash with Ed25519, using the private key associated with our 'identity'
        var signature = PublicKeyAuth.Sign(zomeCallDataToSign, signingKeyPair.KeyPair.PrivateKey);

        Console.WriteLine(String.Format("got signature {0}", signature.Length));

        // Copy all the unsigned zome call fields forward and add the signature to create a real zome call payload
        var realZomeCall = new ZomeCall
        {
            CellId = [zomeCall.cell_id_dna_hash, zomeCall.cell_id_agent_pub_key],
            ZomeName = zomeCall.zome_name,
            FunctionName = zomeCall.fn_name,
            Payload = zomeCall.payload,
            CapSecret = zomeCall.cap_secret,
            Provenance = zomeCall.provenance,
            Signature = signature[0..64],
            Nonce = zomeCall.nonce,
            ExpiresAt = zomeCall.expires_at,
        };

        var appRequest = new AppRequest
        {
            Tag = "call_zome",
            Data = realZomeCall,
        };
        var appRequestInner = MessagePackSerializer.Serialize(appRequest);

        var zomeRequest = new WireMessage(2, "request", appRequestInner);

        // Connect to an app websocket on Holochain. Note that this is going to change per run, so you'll need to update this to connect here!
        var appClient = await Client.create(33564);

        try
        {
            // Actually send the zome call, finally :)
            var response = await appClient.Send(zomeRequest);

            // Check that the response indicates success. My zome returns an empty array response so it's not very interesting, but the response data is here in `response.Data`
            var adminResponse = MessagePackSerializer.Deserialize<AdminResponse>(response.Data);
            if (adminResponse.Type != "zome_called")
            {
                throw new Exception("Got an error, wanted zome called");
            }

            Console.WriteLine("Zome called");
        }
        catch (Exception e)
        {
            Console.WriteLine("Failed to call zome: " + e.ToString());
        }

        // This part is super buggy, please ignore. Shutting down the admin and app websockets. Expect this to fail and dump errors. That's fine as long as the code above printed `Zome called`

        await adminClient.ClientWs.CloseAsync(WebSocketCloseStatus.NormalClosure, "finished", CancellationToken.None);
        adminClient.Handle?.Join();

        await appClient.ClientWs.CloseAsync(WebSocketCloseStatus.NormalClosure, "finished", CancellationToken.None);
        appClient.Handle?.Join();
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

    internal static async Task<Client> create(int port)
    {
        Uri uri = new(String.Format("ws://localhost:{0}", port));

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
    public byte[] Identity { get; }

    public SigningKeyPair(KeyPair keyPair, byte[] signingKey)
    {
        KeyPair = keyPair;
        Identity = signingKey;
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

[MessagePackObject]
public class AppRequest
{
    [Key("type")]
    public string Tag { get; set; }

    [Key("data")]
    public ZomeCall Data { get; set; }
}

[MessagePackObject]
public class ZomeCall
{
    [Key("cell_id")]
    public byte[][] CellId { get; set; }

    [Key("zome_name")]
    public string ZomeName { get; set; }

    [Key("fn_name")]
    public string FunctionName { get; set; }

    [Key("payload")]
    public byte[] Payload { get; set; }

    [Key("cap_secret")]
    public byte[] CapSecret { get; set; }

    [Key("provenance")]
    public byte[] Provenance { get; set; }

    [Key("signature")]
    public byte[] Signature { get; set; }

    [Key("nonce")]
    public byte[] Nonce { get; set; }

    [Key("expires_at")]
    public Int64 ExpiresAt { get; set; }
}
