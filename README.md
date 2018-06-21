# IoT-bot-detection

The widespread adoption of Internet of Things has led to many security issues. Recently, there have been malware attacks on IoT devices, the most prominent one being that of Mirai. IoT devices such as IP cameras, DVRs and routers were compromised by the Mirai malware and later large-scale DDoS attacks were propagated using those infected devices (bots) in October 2016. 

We have developed a practical algorithm which can be used to detect IoT bots infected by Mirai and similar malwares in a real-world large-scale networks (e.g. ISP network). The proposed algorithm leverages the unique network traffic signatures produced by a bot infected with Mirai malware and a novel two-dimensional (2D) packet sampling approach, wherein we sample the packets transmitted by IoT devices both across time and across the devices.

This repository contains files for a software prototype of the proposed bot detection algorithm which will be evaluated on our IoT malware testbed simulating a real-world network of connected IoT and non-IoT devices, gateways, routers and sentinel devices.
