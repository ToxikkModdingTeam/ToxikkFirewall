using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace ToxikkFirewall;

internal class Program
{
  private readonly string[] args;
  private readonly List<int> ports = new();

  private static IPAddress externalIp;

  static void Main(string[] args)
  {
    var prog = new Program(args);
    prog.Run();
  }

  private Program(string[] args)
  {
    this.args = args;
  }

  private void Run()
  {
    if (!ParseArgs())
    {
      ShowUsage();
      return;
    }

    StartProxyThreads();
  }

  private bool ParseArgs()
  {
    if (args.Length < 2)
      return false;

    if (!ParseIpAddress(args[0])) 
      return false;

    for (int i=1; i<args.Length; i++)
    {
      if (!int.TryParse(args[i], out var port) || port <= 0 || port >= 65535)
      {
        Console.Error.WriteLine($"{args[i]} is not a valid port number");
        return false;
      }
      ports.Add(port);
    }

    return true;
  }

  private bool ParseIpAddress(string addr)
  {
    var match = System.Text.RegularExpressions.Regex.Match(addr, @"^(\d+)\.(\d+)\.(\d+)\.(\d+)$");
    if (!match.Success)
      return false;
    var octets = new byte[4];
    for (int i = 0; i < 4; i++)
    {
      if (!int.TryParse(match.Groups[i + 1].Value, out var val) || val >= 255)
        return false;
      octets[i] = (byte)val;
    }

    externalIp = new IPAddress(octets);
    return true;
  }

  private void ShowUsage()
  {
    Console.Error.WriteLine(
      "Usage:\n" +
      Path.GetFileName(this.GetType().Assembly.Location) + " <IPv4> <port1> [<port2> ...]\n" +
      "IPv4: IP address to listen on (must be a specific IP so that it has priority over the game server's 0.0.0.0 listen IP)\n" +
      "port: Port numbers to listen on and forward to the server");
  }

  private void StartProxyThreads()
  {
    foreach (var port in ports)
    {
      var thread = new Thread(() => HandleCommunicationForServerInstanceOnPort(port));
      thread.Start();
    }
  }

  private void HandleCommunicationForServerInstanceOnPort(int port)
  {
    var fromClient = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    fromClient.Bind(new IPEndPoint(externalIp, port));

    var serverEndpoint = new IPEndPoint(IPAddress.Loopback, port);

    Dictionary<EndPoint, ClientInfo> clientToServer = new();
    Dictionary<EndPoint, EndPoint> serverToClient = new();

    var blockedIps = new HashSet<IPAddress>();

    byte[] buffer = new byte[65536];

    DateTime nextCleanup = DateTime.MinValue;

    while (true)
    {
      var list = new List<Socket>(clientToServer.Count + 1);
      list.Add(fromClient);
      list.AddRange(clientToServer.Values.Where(info => info.Socket != null).Select(info => info.Socket));
      Socket.Select(list, null, null, 10 * 1000 * 1000); // 10 sec max wait for performing cleanup

      foreach (var sock in list)
      {
        try
        {
          if (sock == fromClient)
            HandleIncomingClientPacket();
          else
            HandleIncomingServerPacket(sock);
        }
        catch (SocketException ex)
        {
          Console.Error.WriteLine(DateTime.Now + "   " + ex);
        }
      }

      if (DateTime.Now >= nextCleanup)
        CleanupStaleConnections();
    }

    void HandleIncomingClientPacket()
    {
      EndPoint clientEndpoint = new IPEndPoint(IPAddress.Any, 0);
      int len = fromClient.ReceiveFrom(buffer, ref clientEndpoint);

      var remote = (IPEndPoint)clientEndpoint;
      if (blockedIps.Contains(remote.Address))
      {
        Console.WriteLine("blocked " + clientEndpoint);
        return;
      }

      var now = DateTime.Now;

      if (clientToServer.TryGetValue(remote, out var info))
      {
        if (now < info.Timestamp) // drop packets while client is in "connection delay" status
          return;

        info.Timestamp = now;
      }
      else
      {
        // put client in a "connection delay" status and drop the package
        info = new ClientInfo(null, now.AddMilliseconds(3000)); // the unrealfp DoS tool has a maximum wait time of 2sec, so we delay for 3sec
        clientToServer[remote] = info;
        Console.WriteLine("delaying client connection attempt: " + clientEndpoint + " to port " + port);
        return;
      }

      if (info.Socket == null)
      {
        var sockToServer = info.Socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        sockToServer.Connect(serverEndpoint);
        serverToClient[sockToServer.LocalEndPoint] = clientEndpoint;
        Console.WriteLine("connected " + clientEndpoint + " to " + sockToServer.LocalEndPoint + " for target port " + port);
      }

      info.Socket.Send(buffer, len, SocketFlags.None);
    }

    void HandleIncomingServerPacket(Socket sock)
    {
      EndPoint fromEndpoint = new IPEndPoint(IPAddress.Any, 0);
      int len = sock.ReceiveFrom(buffer, ref fromEndpoint);
      if (serverToClient.TryGetValue(sock.LocalEndPoint, out var clientEndpoint))
        fromClient.SendTo(buffer, 0, len, SocketFlags.None, clientEndpoint);
    }

    void CleanupStaleConnections()
    {
      nextCleanup = DateTime.Now + TimeSpan.FromSeconds(30);
      var staleTms = DateTime.Now - TimeSpan.FromSeconds(30);
      var entries = new Dictionary<EndPoint, ClientInfo>(clientToServer);
      var disconnectedIps = new Dictionary<IPAddress, int>();
      foreach (var entry in entries)
      {
        var ep = entry.Key;
        var info = entry.Value;
        if (info.Timestamp < staleTms)
        {
          var ip = ((IPEndPoint)ep).Address;
          disconnectedIps.TryGetValue(ip, out var count);
          disconnectedIps[ip] = count + 1;

          clientToServer.Remove(ep);
          if (info.Socket != null)
          {
            Console.WriteLine("disconnected " + entry.Key + "->" + info.Socket.LocalEndPoint);
            info.Socket.Dispose();
          }
        }
      }

      foreach (var entry in disconnectedIps)
      {
        if (entry.Value >= 4)
        {
          Console.WriteLine("added to ban-list: " + entry.Key);
          blockedIps.Add(entry.Key);
        }
      }
    }

  }

  class ClientInfo
  {
    public Socket Socket;
    public DateTime Timestamp;

    public ClientInfo(Socket socket, DateTime timestamp)
    {
      Socket = socket;
      Timestamp = timestamp;
    }
  }
}