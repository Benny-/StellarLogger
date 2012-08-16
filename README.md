StellarLogger
=============

A game score logger for [Stellar Impact](www.stellar-impact.com)

You need to have [WinPcap](http://www.winpcap.org/install/default.htm) installed and running. Once WinPcap is running, simply start and play a Steller Impact game while stellar logger is running in the background.

![Stellar impact score board](https://raw.github.com/Benny-/StellarLogger/master/img/Score.png)

Stellar logger works on the interface level. It intercepts all incomming packages and uses simple Heuristics (checks the existence of a magic number) to determine if it contains score information from a stellar impact game.

Before stellar logger can listen for incomming packages, you need to select a interface to listen on. This might be different for every computer. You need to use trial and error to find the good one.

![Interface selection](https://raw.github.com/Benny-/StellarLogger/master/img/interfaceSelect.png)

![Stellar logger in listening mode](https://raw.github.com/Benny-/StellarLogger/master/img/Listening.png)

Once it detects a game, it will show you the players and the scores they have. It will append the information to its logfile stellarlog.pcap. The logfile can contain more then 1 game score, but must be stored/renamed/merged(merging using Wireshark as the .pcap format are essetially raw network packages) between every run as stellar logger cant append to it anymore once it is closed. The .pcap files can at any later moment be read by dragging the .pcap file onto the stellar logger executeble.

Listening for packages and using heuristics to extract score can be unreliable. The game's netcode may change or the connection is made using ipv6 (stellar logger does not support ipv6). All this might result in stellar logger from not working at any moment.

