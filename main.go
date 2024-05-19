/*

[TODO]:

	1. To work in multi flag way when you specify few flags rewrite  main loop save (return from handler) output packet with if statements (if ip or mac specified call handler than return outpacket)
	Then in main loop after all changes saved to outpacket - run serialize and write to pcap
	2. Write tcp sequenc/ack recalculate and rewrite func

*/

package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	snapshotLen uint32 = 65000
)

var (
	pcapFile         string
	ipAddr           string
	macAddr          string
	tcpPort          string
	udpPort          string
	tcpPayload       string
	tcpPayloadPrefix string
	udpPayload       string
	udpPayloadPrefix string
)

func main() {

	// Flags:

	flag.StringVar(&pcapFile, "r", "", "Specify pcap file")
	flag.StringVar(&ipAddr, "ip", "", "Specify ipv4 address to change in format old_ipv4=new_ipv4, 192.168.100.1=10.30.12.11")
	flag.StringVar(&macAddr, "mac", "", "Specify mac address to change in folmat old_mac=new_mac, 00:0c:29:1d:ec:95=00:0c:29:6b:7a:f0")
	flag.StringVar(&tcpPort, "tcpport", "", "Specify tcp port to change in format old_tcp_port=new_tcp_port, 12345=8080")
	flag.StringVar(&udpPort, "udpport", "", "Specify udp port to change in format old_udp_port=new_udp_port, 54321=9090")
	flag.StringVar(&tcpPayload, "tcppayload", "", "Specify tcp payload you want to change, old_payload=new_payload - only ascii payload may be changed")
	flag.StringVar(&tcpPayloadPrefix, "tcppayloadprefix", "", "Specify tcp payload you want to be prefixed, -tcppayloadprefix EICAR_")
	flag.StringVar(&udpPayload, "udppayload", "", "Specify udp payload you want to change, old_payload=new_payload - only ascii payload may be changed")
	flag.StringVar(&udpPayloadPrefix, "udppayloadprefix", "", "Specify udp payload you want to be prefixed, -udppayloadprefix EICAR_")

	flag.Parse()

	if pcapFile == "" || (ipAddr == "" && macAddr == "" && tcpPort == "" && udpPort == "" && tcpPayload == "" && tcpPayloadPrefix == "" && udpPayload == "" && udpPayloadPrefix == "") {
		fmt.Println("[!] Only one flag ip/mac/tcpport works at a time [!]")
		flag.Usage()
		os.Exit(0)
	}

	// OPEN PCAP TO READ

	inputHandle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal("Error opening input PCAP file:", err)
	}
	defer inputHandle.Close()

	// // OUTPUT PCAP FILE

	outputFilePath := "output.pcap"
	f, _ := os.Create(outputFilePath)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)
	defer f.Close()

	// Iterate through each packet in the input PCAP file

	packetSource := gopacket.NewPacketSource(inputHandle, inputHandle.LinkType())

	for packet := range packetSource.Packets() {

		switch {
		case ipAddr != "":
			err := changeIpAddress(packet, w, ipAddr)
			if err != nil {
				log.Println("Error changing ip addr", err)
				continue
			}
		case macAddr != "":
			err := changeMACAddress(packet, w, macAddr)
			if err != nil {
				log.Println("Error changing mac addr", err)
				continue
			}
		case tcpPort != "":
			err := changeTCPPort(packet, w, tcpPort)
			if err != nil {
				log.Println("Error changing tcp port", err)
				continue
			}
		case udpPort != "":
			err := changeUDPPort(packet, w, udpPort)
			if err != nil {
				log.Println("Error changing udp port", err)
				continue
			}
		case tcpPayload != "":
			err := changeTCPPayload(packet, w, tcpPayload)
			if err != nil {
				log.Println("Error changing tcp payload", err)
				continue
			}
		case tcpPayloadPrefix != "":
			err := changeTCPPayloadPrefix(packet, w, tcpPayloadPrefix)
			if err != nil {
				log.Println("Error changing tcp payload prefix", err)
				continue
			}
		case udpPayloadPrefix != "":
			err := changeUDPPayloadPrefix(packet, w, udpPayloadPrefix)
			if err != nil {
				log.Println("Error changing udp payload prefix", err)
				continue
			}
		case udpPayload != "":
			err := changeUDPPayload(packet, w, udpPayload)
			if err != nil {
				log.Println("Error changing udp payload", err)
				continue
			}

		default:
			serializeAndSaveToPcap(packet, w)
		}

		//WORKS IN ONE FLAG AT A TIME - in each if statement run handler - return packet, err - then run serialize and write to pcap

	}

}

func changeIpAddress(packet gopacket.Packet, w *pcapgo.Writer, ip string) error {

	ipList := strings.Split(ip, "=")

	// ipv4 parse to array

	oldIP := net.ParseIP(ipList[0])
	oldIP = net.IP{oldIP[12], oldIP[13], oldIP[14], oldIP[15]}

	newIP := net.ParseIP(ipList[1])
	newIP = net.IP{newIP[12], newIP[13], newIP[14], newIP[15]}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)

	if ipLayer != nil {
		ipPacket, _ := ipLayer.(*layers.IPv4)

		if reflect.DeepEqual(ipPacket.SrcIP, oldIP) {
			ipPacket.SrcIP = newIP
		} else if reflect.DeepEqual(ipPacket.DstIP, oldIP) {
			ipPacket.DstIP = newIP
		}

		// Assuming serializeAndSaveToPcap is defined elsewhere and correctly handles saving packets
		serializeAndSaveToPcap(packet, w)
		fmt.Printf("Time: %s From %s to %s Protocol: %s \n", packet.Metadata().Timestamp, ipPacket.SrcIP, ipPacket.DstIP, ipPacket.Protocol)

	}

	return nil
}

func changeMACAddress(packet gopacket.Packet, w *pcapgo.Writer, mac string) error {

	ipList := strings.Split(mac, "=")

	// mac parse to array

	oldMAC, err := net.ParseMAC(ipList[0])
	if err != nil {
		log.Println("Error parsing old MAC address", err)
		return err
	}

	newMAC, err := net.ParseMAC(ipList[1])
	if err != nil {
		log.Println("Error parsing new MAC address", err)
		return err
	}

	ethLayer := packet.Layer(layers.LayerTypeEthernet)

	if ethLayer != nil {
		ethernetPacket, _ := ethLayer.(*layers.Ethernet)

		if reflect.DeepEqual(ethernetPacket.SrcMAC, oldMAC) {
			ethernetPacket.SrcMAC = newMAC
		} else if reflect.DeepEqual(ethernetPacket.DstMAC, oldMAC) {
			ethernetPacket.DstMAC = newMAC
		}

		// Assuming serializeAndSaveToPcap is defined elsewhere and correctly handles saving packets
		serializeAndSaveToPcap(packet, w)
		fmt.Printf("Time: %s Source MAC: %s Destination MAC: %s Ethernet type: %s \n", packet.Metadata().Timestamp, ethernetPacket.SrcMAC, ethernetPacket.DstMAC, ethernetPacket.EthernetType)

	}

	return nil

}

func changeTCPPort(packet gopacket.Packet, w *pcapgo.Writer, tcpPort string) error {
	portList := strings.Split(tcpPort, "=")

	oldTCPport, err := strconv.Atoi(portList[0])
	if err != nil {
		return fmt.Errorf("error parsing old TCP port: %v", err)
	}

	newTCPport, err := strconv.Atoi(portList[1])
	if err != nil {
		return fmt.Errorf("error parsing new TCP port: %v", err)
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if tcpLayer != nil {
		tcpPacket, _ := tcpLayer.(*layers.TCP)
		if tcpPacket.SrcPort == layers.TCPPort(oldTCPport) {
			tcpPacket.SrcPort = layers.TCPPort(newTCPport)
		} else if tcpPacket.DstPort == layers.TCPPort(oldTCPport) {
			tcpPacket.DstPort = layers.TCPPort(newTCPport)
		}

		// Assuming serializeAndSaveToPcap is defined elsewhere and correctly handles saving packets
		serializeAndSaveToPcap(packet, w)
		fmt.Printf("Changed port from %d to %d\n", oldTCPport, newTCPport)
	}

	return nil
}

func serializeAndSaveToPcap(packet gopacket.Packet, w *pcapgo.Writer) error {

	// Serialize the modified packet
	opts := gopacket.SerializeOptions{ComputeChecksums: false,
		FixLengths: false}

	serializedPacket := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializePacket(serializedPacket, opts, packet); err != nil {
		log.Println("Error serializing packet:", err)
		return err
	}

	// Create a new PacketMetadata with correct lengths
	captureInfo := gopacket.CaptureInfo{
		Timestamp:      packet.Metadata().CaptureInfo.Timestamp,
		CaptureLength:  len(serializedPacket.Bytes()), // Use the length of the serialized packet
		Length:         len(serializedPacket.Bytes()), // Use the length of the serialized packet
		InterfaceIndex: packet.Metadata().CaptureInfo.InterfaceIndex,
		AncillaryData:  packet.Metadata().CaptureInfo.AncillaryData,
	}

	// Write the serialized packet to the new PCAP file

	if err := w.WritePacket(captureInfo, serializedPacket.Bytes()); err != nil {
		log.Println("Error writing packet:", err)
		return err
	}

	return nil

}

func changeUDPPort(packet gopacket.Packet, w *pcapgo.Writer, udpPort string) error {

	portList := strings.Split(udpPort, "=")

	oldUDPport, err := strconv.Atoi(portList[0])
	if err != nil {
		return fmt.Errorf("error parsing old UDP port: %v", err)
	}

	newUDPport, err := strconv.Atoi(portList[1])
	if err != nil {
		return fmt.Errorf("error parsing new UDP port: %v", err)
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if udpLayer != nil {
		udpPacket, _ := udpLayer.(*layers.UDP)
		if udpPacket.SrcPort == layers.UDPPort(oldUDPport) {
			udpPacket.SrcPort = layers.UDPPort(newUDPport)
		} else if udpPacket.DstPort == layers.UDPPort(oldUDPport) {
			udpPacket.DstPort = layers.UDPPort(newUDPport)
		}

		// Assuming serializeAndSaveToPcap is defined elsewhere and correctly handles saving packets
		serializeAndSaveToPcap(packet, w)
		fmt.Printf("Changed port from %d to %d\n", oldUDPport, newUDPport)
	}

	return nil

}

func changeTCPPayload(packet gopacket.Packet, w *pcapgo.Writer, tcpPayload string) error {

	payloadList := strings.Split(tcpPayload, "=")

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ethLayer != nil && ipLayer != nil && tcpLayer != nil {
		ethernetPacket, _ := ethLayer.(*layers.Ethernet)
		ipPacket, _ := ipLayer.(*layers.IPv4)
		tcpPacket, _ := tcpLayer.(*layers.TCP)

		if len(tcpPacket.Payload) >= len(payloadList[1]) && (strings.Contains(strings.TrimSpace(string(tcpPacket.Payload)), payloadList[0])) {

			newPayload := append([]byte(payloadList[1]), tcpPacket.Payload[:len(tcpPacket.Payload)-len(payloadList[1])]...)

			tcpPacket.Payload = newPayload
			fmt.Printf("Changed payload from %s to %s\n", payloadList[0], tcpPacket.Payload)

		}
		//=========================================
		//RECALCULATE SEQ/ACK
		//=========================================
		// Adjust SEQ and ACK numbers
		//adjustSeqAndAckNumbers(tcpPacket, payloadLenDifference, streams, ipPacket)

		// Set network layer for TCP checksum computation
		tcpPacket.SetNetworkLayerForChecksum(ipPacket)

		// Serialize the modified packet
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

		// Serialize layers in the correct order
		if err := gopacket.SerializeLayers(buf, opts,
			ethernetPacket,
			ipPacket,
			tcpPacket,
			gopacket.Payload(tcpPacket.Payload),
		); err != nil {
			log.Fatal("Error serializing layers:", err)
		}

		// Create a new PacketMetadata with correct lengths
		captureInfo := gopacket.CaptureInfo{
			Timestamp:      packet.Metadata().CaptureInfo.Timestamp,
			CaptureLength:  len(buf.Bytes()), // Use the length of the serialized packet
			Length:         len(buf.Bytes()), // Use the length of the serialized packet
			InterfaceIndex: packet.Metadata().CaptureInfo.InterfaceIndex,
			AncillaryData:  packet.Metadata().CaptureInfo.AncillaryData,
		}

		// Write the serialized packet to the new PCAP file
		if err := w.WritePacket(captureInfo, buf.Bytes()); err != nil {
			log.Fatal("Error writing packet:", err)
		}
	}
	return nil
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	source := rand.NewSource(time.Now().UnixNano())
	r := rand.New(source)
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}
	return string(b)
}

func changeTCPPayloadPrefix(packet gopacket.Packet, w *pcapgo.Writer, tcpPayloadPrefix string) error {

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ethLayer != nil && ipLayer != nil && tcpLayer != nil {
		ethernetPacket, _ := ethLayer.(*layers.Ethernet)
		ipPacket, _ := ipLayer.(*layers.IPv4)
		tcpPacket, _ := tcpLayer.(*layers.TCP)

		if len(tcpPacket.Payload) >= len(tcpPayloadPrefix) {

			tcpPacket.Payload = []byte(fmt.Sprintf(tcpPayloadPrefix, generateRandomString(len(tcpPacket.Payload)-len(tcpPayloadPrefix)-1)))
		}

		//=========================================
		//RECALCULATE SEQ/ACK
		//=========================================
		// Adjust SEQ and ACK numbers
		//adjustSeqAndAckNumbers(tcpPacket, payloadLenDifference, streams, ipPacket)

		// Set network layer for TCP checksum computation
		tcpPacket.SetNetworkLayerForChecksum(ipPacket)

		// Serialize the modified packet
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

		// Serialize layers in the correct order
		if err := gopacket.SerializeLayers(buf, opts,
			ethernetPacket,
			ipPacket,
			tcpPacket,
			gopacket.Payload(tcpPacket.Payload),
		); err != nil {
			log.Fatal("Error serializing layers:", err)
		}

		// Create a new PacketMetadata with correct lengths
		captureInfo := gopacket.CaptureInfo{
			Timestamp:      packet.Metadata().CaptureInfo.Timestamp,
			CaptureLength:  len(buf.Bytes()), // Use the length of the serialized packet
			Length:         len(buf.Bytes()), // Use the length of the serialized packet
			InterfaceIndex: packet.Metadata().CaptureInfo.InterfaceIndex,
			AncillaryData:  packet.Metadata().CaptureInfo.AncillaryData,
		}

		// Write the serialized packet to the new PCAP file
		if err := w.WritePacket(captureInfo, buf.Bytes()); err != nil {
			log.Fatal("Error writing packet:", err)
		}
	}
	return nil

}

func changeUDPPayloadPrefix(packet gopacket.Packet, w *pcapgo.Writer, udpPayloadPrefix string) error {

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if ethLayer != nil && ipLayer != nil && udpLayer != nil {
		ethernetPacket, _ := ethLayer.(*layers.Ethernet)
		ipPacket, _ := ipLayer.(*layers.IPv4)
		udpPacket, _ := udpLayer.(*layers.UDP)

		if len(udpPacket.Payload) >= len(udpPayloadPrefix) {

			udpPacket.Payload = []byte(fmt.Sprintf(tcpPayloadPrefix, generateRandomString(len(udpPacket.Payload)-len(udpPayloadPrefix)-1)))
		}

		//=========================================
		//RECALCULATE SEQ/ACK
		//=========================================
		// Adjust SEQ and ACK numbers
		//adjustSeqAndAckNumbers(tcpPacket, payloadLenDifference, streams, ipPacket)

		// Set network layer for TCP checksum computation
		udpPacket.SetNetworkLayerForChecksum(ipPacket)

		// Serialize the modified packet
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

		// Serialize layers in the correct order
		if err := gopacket.SerializeLayers(buf, opts,
			ethernetPacket,
			ipPacket,
			udpPacket,
			gopacket.Payload(udpPacket.Payload),
		); err != nil {
			log.Fatal("Error serializing layers:", err)
		}

		// Create a new PacketMetadata with correct lengths
		captureInfo := gopacket.CaptureInfo{
			Timestamp:      packet.Metadata().CaptureInfo.Timestamp,
			CaptureLength:  len(buf.Bytes()), // Use the length of the serialized packet
			Length:         len(buf.Bytes()), // Use the length of the serialized packet
			InterfaceIndex: packet.Metadata().CaptureInfo.InterfaceIndex,
			AncillaryData:  packet.Metadata().CaptureInfo.AncillaryData,
		}

		// Write the serialized packet to the new PCAP file
		if err := w.WritePacket(captureInfo, buf.Bytes()); err != nil {
			log.Fatal("Error writing packet:", err)
		}
	}
	return nil

}

func changeUDPPayload(packet gopacket.Packet, w *pcapgo.Writer, udpPayload string) error {

	payloadList := strings.Split(udpPayload, "=")

	//fmt.Println(payloadList)

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	//fmt.Println(ipLayer)

	if ethLayer != nil && ipLayer != nil && udpLayer != nil {
		ethernetPacket, _ := ethLayer.(*layers.Ethernet)
		ipPacket, _ := ipLayer.(*layers.IPv4)
		udpPacket, _ := udpLayer.(*layers.UDP)

		if len(udpPacket.Payload) >= len(payloadList[1]) && (strings.Contains(strings.TrimSpace(string(udpPacket.Payload)), payloadList[0])) {

			newPayload := append([]byte(payloadList[1]), udpPacket.Payload[:len(udpPacket.Payload)-len(payloadList[1])]...)

			udpPacket.Payload = newPayload
			fmt.Printf("Changed payload from %s to %s\n", payloadList[0], udpPacket.Payload)

		}
		//=========================================
		//RECALCULATE SEQ/ACK
		//=========================================
		// Adjust SEQ and ACK numbers
		//adjustSeqAndAckNumbers(tcpPacket, payloadLenDifference, streams, ipPacket)

		// Set network layer for TCP checksum computation
		udpPacket.SetNetworkLayerForChecksum(ipPacket)

		// Serialize the modified packet
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

		// Serialize layers in the correct order
		if err := gopacket.SerializeLayers(buf, opts,
			ethernetPacket,
			ipPacket,
			udpPacket,
			gopacket.Payload(udpPacket.Payload),
		); err != nil {
			log.Fatal("Error serializing layers:", err)
		}

		// Create a new PacketMetadata with correct lengths
		captureInfo := gopacket.CaptureInfo{
			Timestamp:      packet.Metadata().CaptureInfo.Timestamp,
			CaptureLength:  len(buf.Bytes()), // Use the length of the serialized packet
			Length:         len(buf.Bytes()), // Use the length of the serialized packet
			InterfaceIndex: packet.Metadata().CaptureInfo.InterfaceIndex,
			AncillaryData:  packet.Metadata().CaptureInfo.AncillaryData,
		}

		// Write the serialized packet to the new PCAP file
		if err := w.WritePacket(captureInfo, buf.Bytes()); err != nil {
			log.Fatal("Error writing packet:", err)
		}
	}
	return nil
}

//func SeqAckRecalculate(packet gopacket.Packet, w *pcapgo.Writer, ip string) error {}

// func adjustSeqAndAckNumbers(tcpPacket *layers.TCP, payloadLenDifference int, streams map[string]*tcpStream, ipPacket *layers.IPv4) {
// 	streamID := fmt.Sprintf("%s:%d-%s:%d", ipPacket.SrcIP, tcpPacket.SrcPort, ipPacket.DstIP, tcpPacket.DstPort)
// 	stream, exists := streams[streamID]
// 	if !exists {
// 		stream = &tcpStream{seqAdjustment: 0, ackAdjustment: 0}
// 		streams[streamID] = stream
// 	}

// 	log.Println("Stream:", streamID, stream, exists)

// 	// Adjust SEQ number
// 	tcpPacket.Seq += uint32(stream.seqAdjustment)
// 	stream.seqAdjustment += payloadLenDifference

// 	// Adjust ACK number
// 	tcpPacket.Ack += uint32(stream.ackAdjustment)
// 	stream.ackAdjustment += payloadLenDifference

// 	// Adjustments for the reverse direction stream
// 	reverseStreamID := fmt.Sprintf("%s:%d-%s:%d", ipPacket.DstIP, tcpPacket.DstPort, ipPacket.SrcIP, tcpPacket.SrcPort)
// 	reverseStream, exists := streams[reverseStreamID]
// 	if !exists {
// 		reverseStream = &tcpStream{seqAdjustment: 0, ackAdjustment: 0}
// 		streams[reverseStreamID] = reverseStream
// 	}

// 	log.Println("Reverse Stream:", reverseStreamID, reverseStream, exists)

// 	// Update reverse stream adjustments
// 	reverseStream.ackAdjustment += payloadLenDifference
// }
