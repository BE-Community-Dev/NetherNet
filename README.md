# NetherNet
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](src/NetherNet/NetherNet.csproj)
> [Chinese](readme_zh.md)
A pure C# implementation of the NetherNet networking protocol for Minecraft Bedrock and real-time applications. This library provides peer-to-peer message transport over WebRTC data channels, with DTLS identity assertions, ICE negotiation, and pluggable HTTP or LAN signaling.
This is a C# implementation of the NetherNet protocol.
---
## Installation
### Requirements
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later
### Add to your project
```bash
dotnet add package ArkMirage.NetherNet
dotnet add package ArkMirage.NetherNet.Endpoint
```
Or add a project reference:
```xml
<ItemGroup>
  <ProjectReference Include="path/to/src/NetherNet/NetherNet.csproj" />
  <ProjectReference Include="path/to/src/NetherNet.Endpoint/NetherNet.Endpoint.csproj" />
</ItemGroup>
```
---
## Quick Start
### Start a server
```csharp
using NetherNet;
using NetherNet.Endpoint;

var server = Handler.New();
var listener = await new ListenConfig
{
    AllowAnonymous = true,
    DisableTrickleICE = true,
    Log = Console.WriteLine,
}.ListenAsync(server);
server.Start("0.0.0.0:19132");

Console.WriteLine("listening on NetherNet, address=0.0.0.0:19132");
while (true)
{
    var conn = await listener.AcceptAsync();
    Console.WriteLine($"connected remoteAddr={conn.RemoteAddr()} localAddr={conn.LocalAddr()}");
    _ = Task.Run(async () =>
    {
        while (true)
        {
            byte[] data = await conn.ReceiveAsync(MessageReliability.Reliable);
            conn.Send(data, MessageReliability.Reliable); // Echo back
        }
    });
}
```
### Connect as a client
```csharp
using NetherNet;
using NetherNet.Endpoint;

var client = Client.New();
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
var conn = await new Dialer
{
    DisableTrickleICE = true,
    Log = Console.WriteLine,
}.DialContextAsync(cts.Token, "http://127.0.0.1:19132", client);

Console.WriteLine($"Connected to {conn.RemoteAddr()}");
conn.Send(System.Text.Encoding.UTF8.GetBytes("Hello, NetherNet!"), MessageReliability.Reliable);
byte[] response = await conn.ReceiveAsync(MessageReliability.Reliable);
Console.WriteLine($"Received: {System.Text.Encoding.UTF8.GetString(response)}");
conn.Close();
```
### Ping a server (HTTP status)
```csharp
var client = NetherNet.Endpoint.Client.New();
var status = await client.StatusAsync(CancellationToken.None, "http://127.0.0.1:19132");
Console.WriteLine($"{status.ServerName}: {status.PlayerCount}/{status.MaxPlayerCount} ({status.Version})");
```
`PingContextAsync` returns the same server information encoded as RakNet pong data.
### LAN discovery
NetherNet peers on the same network discover each other over UDP port **7551** using encrypted broadcast packets. Server information is advertised with `ServerData`:
```csharp
using NetherNet.Discovery;

byte[] pongData = new ServerData
{
    ServerName = "My Server",
    Protocol = 686,
    VersionString = "1.21.0",
    LevelName = "Bedrock level",
    GameType = GameType.Survival,
    PlayerCount = 0,
    MaxPlayerCount = 10,
    AcceptsOnlineAuth = true,
    AcceptsSelfSignedAuth = true,
    ConnectionType = 4,
}.MarshalBinary();
```
---
## API Overview
### Core Types
| Type | Description |
|------|-------------|
| `Listener` | Server listener — negotiates inbound connections over an `ISignaling` transport and accepts them |
| `Dialer` | Client dialer — negotiates an outbound connection to a remote network ID |
| `Conn` | Connection instance — provides `Send()` / `ReceiveAsync()` for data exchange |
| `Identity` | P-384 identity key used to sign and verify DTLS fingerprint assertions |
| `Signal` | Signaling message (`CONNECTREQUEST`, `CONNECTRESPONSE`, `CANDIDATEADD`, `CONNECTERROR`) |
| `ISignaling` | Transport interface implemented by the HTTP and LAN signaling backends |
| `MessageReliability` | Enum of available data channel reliability levels |
| `Addr` | Local or remote address of a connection, including ICE candidates |
| `NetherNetException` | Error type thrown by the library |
### Message Reliability
| Level | Value | Data Channel | Description |
|-------|-------|--------------|-------------|
| `Reliable` | 0 | `ReliableDataChannel` | Reliable and ordered (default) |
| `Unreliable` | 1 | `UnreliableDataChannel` | Unordered with limited retransmits — single-segment messages only |
### Signaling Backends
| Type | Description |
|------|-------------|
| `NetherNet.Endpoint.Handler` | HTTP server signaling — serves `GET /v1/join` and `POST /v1/join/{networkId}` |
| `NetherNet.Endpoint.Client` | HTTP client signaling — joins a server by URL, also used for status pings |
| `NetherNet.Discovery.Listener` | LAN discovery signaling over UDP (default port 7551) |
### Configuration
```csharp
public sealed class Dialer
{
    public ulong ConnectionID;                                        // Connection ID (random when zero)
    public Action<string>? Log;                                       // Log callback
    public Identity? Identity;                                        // Client identity for signed assertions
    public Func<CancellationToken, string, string, Task<ECDsa?>>? VerifyServerToken; // Custom server token verification
    public bool AllowIdentitylessServer;                              // Accept answers without an identity
    public IceGatherPolicy IceGatherPolicy;                           // ICE candidate gathering policy
    public Func<CancellationToken, Task<Credentials?>>? Credentials;  // ICE server credentials
    public bool DisableTrickleICE;                                    // Disable trickle ICE
}
public sealed class ListenConfig
{
    public Action<string>? Log;                                       // Log callback
    public Func<CancellationToken, Conn, CancellationTokenSource?>? ConnContext;       // Per-connection context
    public Func<CancellationToken, CancellationTokenSource?>? NegotiationContext;      // Per-negotiation context
    public Func<CancellationToken, Task<Identity>>? IssueServerIdentity;               // Server identity factory
    public Func<CancellationToken, string, Task<ECDsa?>>? VerifyClientToken;           // Custom client token verification
    public bool AllowAnonymous;                                       // Allow clients without an identity
    public IceGatherPolicy IceGatherPolicy;                           // ICE candidate gathering policy
    public bool DisableTrickleICE = true;                             // Disable trickle ICE
}
```
---
## License
This project is licensed under the [GNU General Public License v3.0](LICENSE).
