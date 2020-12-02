package app;

import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.*;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
//import org.jnetpcap.packet.PcapPacket;
//import org.jnetpcap.packet.PcapPacketHandler;
//import org.jnetpcap.protocol.network.Ip4;
import java.util.Scanner;
public class Sniff_test {
	
	public static void main(String[] args)
	{
		List<PcapIf> devices = new ArrayList<PcapIf>();
		StringBuilder errormsg = new StringBuilder();
		int t = Pcap.findAllDevs(devices, errormsg); // no. of devices
		if (t == Pcap.NOT_OK || devices.isEmpty()) 
	     {
	         System.err.printf("Can't read list of devices, error is %s",
	                 errormsg.toString());
	         return;
	     }
		
		 System.out.println("Network devices found:");
	     int i = 0;
	     for (PcapIf device : devices) 
	     {
	         String description = (device.getDescription() != null) ? device
	                 .getDescription() : "No description available";
	         //msg.append(Integer.toString(i++)+ " "+device.getName()+" "+description);
	         System.out.println( i++ +" " +description+" "+device.getName() );
	     } 
	     System.out.println(devices.size());
	     
	     System.out.println("choose device");
	     Scanner sc = new Scanner(System.in);
	     int d=sc.nextInt();
	     
	     
	     PcapIf device = devices.get(d); // Get first device in list
	     
	     System.out.println("\nChoosing " +device.getDescription()  +" on your behalf:\n");
	     /*
	     System.out.printf("\nChoosing '%s' on your behalf:\n",
	             (device.getDescription() != null) ? device.getDescription()
	                     : device.getName());
	                     */
	     int snaplen = 64 * 1024; // Capture all packets, no trucation
	     int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
	     int timeout = 30000; // 30 seconds in millisecond
	     Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errormsg);
	     if (pcap == null) {
	         System.err.printf("Error while opening device for capture: "
	                 + errormsg.toString());
	         return ;
	     }
	     PcapPacketHandler<String> jpacketHandler = 
	     		
	     new PcapPacketHandler<String>()
	     {
	         public void nextPacket(PcapPacket packet, String user) {
	             byte[] data = packet.getByteArray(0, packet.size()); // the package data
	             byte[] sIP = new byte[4];
	             byte[] dIP = new byte[4];
	             Ip4 ip = new Ip4();
	             if (packet.hasHeader(ip) == false) {
	                 return; // Not IP packet
	             }
	             ip.source(sIP);
	             ip.destination(dIP);
	             /* Use jNetPcap format utilities */
	             String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
	             String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
	             
	            
	             System.out.println("srcIP=" + sourceIP + 
	                     " dstIP=" + destinationIP + 
	                     " caplen=" + packet.getCaptureHeader().caplen());
	         }
	     };
	     // capture first 10 packages
	     pcap.loop(10, jpacketHandler, "jNetPcap");
	     pcap.close(); 
	}

}
