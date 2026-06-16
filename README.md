# DPI Engine - Deep Packet Inspection System

A high-performance, multi-threaded Deep Packet Inspection (DPI) engine written in Java. This system analyzes network traffic from PCAP files, identifies applications by inspecting packet payloads (such as extracting Server Name Indication (SNI) from TLS Client Hello packets), and filters or blocks traffic based on user-defined rules.

## Features

- **Deep Packet Inspection**: Parses Ethernet, IP, TCP/UDP headers and extracts application-layer data (e.g., TLS SNI).
- **Traffic Filtering**: Block packets based on Source IP, Application name (e.g., YouTube, Facebook), or Domain substring.
- **Multi-threaded Architecture**: Uses Load Balancers (LBs) and Fast Path Processors (FPs) to handle large volumes of packets concurrently.
- **PCAP Support**: Reads and writes standard PCAP files for easy integration with network analysis tools like Wireshark.

## Prerequisites

- **Java 17** or higher
- **Maven** 3.6+

## Building the Project

The project uses Maven for dependency management and building. To compile the code and build an executable fat JAR containing all dependencies:

```bash
mvn clean package
```

This will generate the executable JAR file at `target/packet-analyzer-1.0-SNAPSHOT-jar-with-dependencies.jar`.

## Usage

```bash
java -jar target/packet-analyzer-1.0-SNAPSHOT-jar-with-dependencies.jar <input.pcap> <output.pcap> [options]
```

### Arguments

- `input.pcap`: Input PCAP file (captured user traffic)
- `output.pcap`: Output PCAP file (filtered traffic)

### Options

- `--block-ip <ip>`: Block packets from source IP (e.g., `192.168.1.50`)
- `--block-app <app>`: Block application (e.g., `YouTube`, `Facebook`)
- `--block-domain <dom>`: Block domain (substring match)
- `--lbs <n>`: Number of load balancer threads (default: 2)
- `--fps <n>`: Fast Path (FP) threads per LB (default: 2)

### Example

Filter `capture.pcap` to `filtered.pcap`, blocking YouTube and a specific IP address, using custom thread settings:

```bash
java -jar target/packet-analyzer-1.0-SNAPSHOT-jar-with-dependencies.jar capture.pcap filtered.pcap \
    --block-app YouTube \
    --block-ip 192.168.1.50 \
    --lbs 2 \
    --fps 2
```

## Creating Test Data

A Python script is included to generate a test PCAP file with sample traffic:

```bash
python3 generate_test_pcap.py
```
This creates a PCAP file containing simulated network traffic which you can use for testing the engine.

## Understanding the Output

When you run the engine, it will output a detailed processing report containing:
- The active thread configuration and blocking rules.
- Total packets read, forwarded, and dropped.
- Thread statistics (how many packets each Load Balancer/Fast Path thread handled).
- An application breakdown showing the classification of the traffic (e.g., HTTPS, DNS, YouTube).
- A list of detected SNIs / Domains.

## Project Structure

- `src/main/java/packetanalyzer/dpi/` - Core DPI engine components (DPIEngine, MainDPI, LoadBalancer, FastPathProcessor, SNIExtractor)
- `src/main/java/packetanalyzer/models/` - Data models (RawPacket, ParsedPacket, Protocol, etc.)
- `src/main/java/packetanalyzer/PacketParser.java` - Parses raw PCAP bytes into structured packet objects
- `src/main/java/packetanalyzer/PcapReader.java` - Reads the PCAP file format
