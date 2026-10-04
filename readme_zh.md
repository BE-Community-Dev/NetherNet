# NetherNet
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](src/NetherNet/NetherNet.csproj)
> [English](README.md)
NetherNet 网络协议的纯 C# 实现，面向 Minecraft 基岩版与实时应用。本库通过 WebRTC 数据通道提供点对点消息传输，包含 DTLS 身份断言、ICE 协商，以及可插拔的 HTTP / 局域网信令。
本项目是 NetherNet 协议的 C# 实现。
---
## 安装
### 环境要求
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) 或更高版本
### 添加到项目
```bash
dotnet add package ArkMirage.NetherNet
dotnet add package ArkMirage.NetherNet.Endpoint
```
或添加项目引用：
```xml
<ItemGroup>
  <ProjectReference Include="path/to/src/NetherNet/NetherNet.csproj" />
  <ProjectReference Include="path/to/src/NetherNet.Endpoint/NetherNet.Endpoint.csproj" />
</ItemGroup>
```
---
## 快速开始
### 启动服务端
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
            conn.Send(data, MessageReliability.Reliable); // 回显
        }
    });
}
```
### 客户端连接
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
### 探测服务端状态（HTTP）
```csharp
var client = NetherNet.Endpoint.Client.New();
var status = await client.StatusAsync(CancellationToken.None, "http://127.0.0.1:19132");
Console.WriteLine($"{status.ServerName}: {status.PlayerCount}/{status.MaxPlayerCount} ({status.Version})");
```
`PingContextAsync` 返回以 RakNet pong 数据编码的同一份服务端信息。
### 局域网发现
同一网络中的 NetherNet 节点通过 UDP **7551** 端口以加密广播包互相发现。服务端信息通过 `ServerData` 对外广播：
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
## API 概览
### 核心类型
| 类型 | 说明 |
|------|------|
| `Listener` | 服务端监听器 —— 基于 `ISignaling` 传输协商入站连接并接受连接 |
| `Dialer` | 客户端拨号器 —— 向远端 network ID 协商出站连接 |
| `Conn` | 连接实例 —— 通过 `Send()` / `ReceiveAsync()` 收发数据 |
| `Identity` | P-384 身份密钥，用于签名与校验 DTLS 指纹断言 |
| `Signal` | 信令消息（`CONNECTREQUEST`、`CONNECTRESPONSE`、`CANDIDATEADD`、`CONNECTERROR`） |
| `ISignaling` | 传输接口，由 HTTP 与局域网信令后端实现 |
| `MessageReliability` | 数据通道可靠性等级枚举 |
| `Addr` | 连接的本地或远端地址，包含 ICE 候选 |
| `NetherNetException` | 本库抛出的错误类型 |
### 消息可靠性
| 等级 | 值 | 数据通道 | 说明 |
|------|----|----------|------|
| `Reliable` | 0 | `ReliableDataChannel` | 可靠且有序（默认） |
| `Unreliable` | 1 | `UnreliableDataChannel` | 无序且限制重传 —— 仅支持单段消息 |
### 信令后端
| 类型 | 说明 |
|------|------|
| `NetherNet.Endpoint.Handler` | HTTP 服务端信令 —— 提供 `GET /v1/join` 与 `POST /v1/join/{networkId}` |
| `NetherNet.Endpoint.Client` | HTTP 客户端信令 —— 通过 URL 加入服务端，也用于状态探测 |
| `NetherNet.Discovery.Listener` | 基于 UDP 的局域网发现信令（默认端口 7551） |
### 配置
```csharp
public sealed class Dialer
{
    public ulong ConnectionID;                                        // 连接 ID（为 0 时随机生成）
    public Action<string>? Log;                                       // 日志回调
    public Identity? Identity;                                        // 用于签名断言的客户端身份
    public Func<CancellationToken, string, string, Task<ECDsa?>>? VerifyServerToken; // 自定义服务端令牌校验
    public bool AllowIdentitylessServer;                              // 允许不带身份的服务端应答
    public IceGatherPolicy IceGatherPolicy;                           // ICE 候选收集策略
    public Func<CancellationToken, Task<Credentials?>>? Credentials;  // ICE 服务器凭据
    public bool DisableTrickleICE;                                    // 关闭 trickle ICE
}
public sealed class ListenConfig
{
    public Action<string>? Log;                                       // 日志回调
    public Func<CancellationToken, Conn, CancellationTokenSource?>? ConnContext;       // 按连接创建上下文
    public Func<CancellationToken, CancellationTokenSource?>? NegotiationContext;      // 按协商创建上下文
    public Func<CancellationToken, Task<Identity>>? IssueServerIdentity;               // 服务端身份工厂
    public Func<CancellationToken, string, Task<ECDsa?>>? VerifyClientToken;           // 自定义客户端令牌校验
    public bool AllowAnonymous;                                       // 允许不带身份的客户端
    public IceGatherPolicy IceGatherPolicy;                           // ICE 候选收集策略
    public bool DisableTrickleICE = true;                             // 关闭 trickle ICE
}
```
---
## 许可证
本项目基于 [GNU 通用公共许可证 v3.0](LICENSE) 授权。
