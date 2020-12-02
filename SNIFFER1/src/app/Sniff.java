package app;
// ////////////// remove all static that are not meant for main method
import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.*;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;


public class Sniff 
{

 List<PcapIf> devices = new ArrayList<PcapIf>();
  StringBuilder errmsg = new StringBuilder();

 public static void main(String[] args) 
 {
/*
        int t = Pcap.findAllDevs(devices, errormsg); // 2 arrugement : array list of nic and a string
        
         capture(t, devices, errormsg);

        select(number(), devices, errormsg); 	
       
       capture(vart(devices, errmsg), devices, errmsg);
      System.out.println(capture(vart(devices, errmsg), devices, errmsg));
 */
}
 
 public void clr()
 {
	 devices.clear();
 }
 
 public  List<PcapIf> dev()
 {
	 
	 return devices;
 }
 
 
 public  int vart(List<PcapIf> devices, StringBuilder errormsg) // t
 {
	 int t = Pcap.findAllDevs(devices, errormsg); 
	 return t ;
 }
 
 
 public  StringBuilder errmsg()
 {
	
	 return errmsg;
 }
 
 public  StringBuilder select(int d, List<PcapIf> devices, StringBuilder errormsg) 
 {
	 StringBuilder sb = new StringBuilder("\n");
	 PcapIf device = devices.get(d); // Get first device in list
	 sb.append("\nChoosing " +device.getDescription()  +" on your behalf:\n");
     
      	System.out.printf("\nChoosing '%s' on your behalf:\n",
             (device.getDescription() != null) ? device.getDescription()
                     : device.getName());
     
     int snaplen = 64 * 1024; // Capture all packets, no trucation
     int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
     int timeout = 5000; // 5 seconds in millisecond
     Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errormsg);
     if (pcap == null) {
         System.err.printf("Error while opening device for capture: "
                 + errormsg.toString());
         return sb;
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
             sb.append("srcIP=" + sourceIP + " dstIP=" + destinationIP + " caplen=" + packet.getCaptureHeader().caplen() +"\n");
         }
     };
     // capture first 10 packages
     pcap.loop(10, jpacketHandler, "jNetPcap");
     pcap.close();
     
     return sb;
	}

 public  StringBuilder capture(int t , List<PcapIf> devices, StringBuilder errormsg) 
 {
	//devices.clear();
	StringBuilder msg = new StringBuilder("\nNetwork Devices Found: \n");
	 if (t == Pcap.NOT_OK || devices.isEmpty()) 
     {
         System.err.printf("Can't read list of devices, error is %s",
                 errormsg.toString());
         System.exit(0);;
     }
     
     System.out.println("Network devices found:");
     //int i = 0;
     //for (PcapIf device : devices) 
     for(int i=0;i<devices.size(); i++)
     {
         String description = (devices.get(i).getDescription() != null) ? devices.get(i)
                 .getDescription() : "No description available";
         StringBuilder currentdev = new StringBuilder(devices.get(i).getName());
        
  
         if(!(currentdev.toString()).contains("Loopback"))
        	 msg.append(Integer.toString(i) +" " +description +" "+devices.get(i).getName()+" " +"\n");
         //System.out.println( i++ +" "+device.getName() +" " +description);
     } 
     return msg;
 }
 
 }

