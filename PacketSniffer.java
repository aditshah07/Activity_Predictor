import java.io.File;
import java.util.*;

import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapIf;  
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;  
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;  
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.util.PcapPacketArrayList;

import weka.classifiers.Classifier;
import weka.classifiers.Evaluation;
import weka.classifiers.lazy.IBk;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.converters.CSVLoader;
  
  
public class packetSniffer {  
	protected static final long Starttime = System.currentTimeMillis();
	 
    public static void main(String[] args) throws Exception{
    	// referred jnetpcap.com/examples
        List<PcapIf> alldevs = new ArrayList<PcapIf>();  
        StringBuilder errbuf = new StringBuilder();  
        Scanner src = new Scanner(System.in);
        //List devices on the system 
        int r = Pcap.findAllDevs(alldevs, errbuf);  
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
            System.out.println("error: " + errbuf.toString());  
            return;  
        }  
  
        System.out.println("Network devices:");  
  
        int i = 0;  
        for (PcapIf device : alldevs) {  
            String description =  (device.getDescription() != null) ? device.getDescription() : "No description available";  
            System.out.println(i++ + ": "+ device.getName() + ": " + description);  
        }  
        System.out.println("Enter the number of the device to capture");
        int input = src.nextInt();

        PcapIf device = alldevs.get(input);    
        int snaplen = 64 * 1024;          
        int flags = Pcap.MODE_PROMISCUOUS; 
        int timeout = 1 * 1000;          
        final Pcap pcap =  
            Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
        
        if (pcap == null) {  
            System.out.println("Error while opening device for capture: " + errbuf.toString());  
            return;  
        }  
  
        //Capture the live packet for 30 Seconds
        PcapPacketHandler<ArrayList> jpacketHandler = new PcapPacketHandler<ArrayList>() {

        	int size =0;
        	int tcp_size = 0;
        	int udp_size = 0;
        	int counter = 0;
        	int tcp_counter = 0;
        	int udp_counter = 0;
        	Ip4 ip = new Ip4();
        	Tcp tcp = new Tcp();
        	Udp udp = new Udp();
        	Http http = new Http();
        	int a = 0;
        	long capture_time=0;
        	long diff_time=0;
        	long Start = System.currentTimeMillis();
            public void nextPacket(PcapPacket packet, ArrayList arraylist) { 
                
                //Break out of the infinite loop after 30sec
            	if(System.currentTimeMillis()>Start+30000){
            		if(a==0){
            			double avg_time=0;
            			if(diff_time!=0 & counter!=0){
            				avg_time = (double)diff_time/(double)(counter-1);
            			}
            			int avg = (int) avg_time;
            			arraylist.add(Integer.toString(size));
            			arraylist.add(Integer.toString(counter));
            			arraylist.add(Integer.toString(tcp_counter));
            			arraylist.add(Integer.toString(udp_counter));
            			arraylist.add(Integer.toString(udp_size));
            			arraylist.add(Integer.toString(tcp_size));
            			arraylist.add(Integer.toString(avg));
            			a++;
            		}
            	
                	pcap.breakloop();
                }
            	
                // Capture udp packet on port 443(Https) and 80(Http) and extract data
            	if(packet.hasHeader(udp)){
            		if(udp.destination() == 443|| udp.destination() == 80){
            			size = size + packet.size();
            			udp_size = udp_size + packet.size();
            			counter++;
            			udp_counter++;

                        // 1st packet arived at port 80 or port 443, so just store the timstamp of arrival
            			if(counter==1){
            				capture_time = packet.getCaptureHeader().timestampInMillis();
            			}else{
                            // Compute the difference in arrival of two packets
            				diff_time = diff_time + (packet.getCaptureHeader().timestampInMillis() - capture_time);
            				capture_time = packet.getCaptureHeader().timestampInMillis();
            			}
            		}
            	}

                // Capture tcp packet on port 443(HTTPS) and 80(HTTP) and extract data
            	if (packet.hasHeader(tcp)) {
            		if(tcp.destination() == 443|| tcp.destination() == 80){
            			size = size + packet.size();
            			tcp_size = tcp_size + packet.size();
            			counter++;
            			tcp_counter++;
            			
                        // 1st packet arived at port 80 or port 443, so just store the timstamp of arrival
	            		if(counter==1){
	        				capture_time = packet.getCaptureHeader().timestampInMillis();
	        				
	        			}else{
                            // Compute the difference in arrival of two packets
	        				diff_time = diff_time + (packet.getCaptureHeader().timestampInMillis() - capture_time);
	        				capture_time = packet.getCaptureHeader().timestampInMillis();
	        				
	        			}
            		}
            	}
            	
            }  
        };  
  
        
        ArrayList <String>arraylist = new ArrayList<String>();

        pcap.loop(pcap.LOOP_INFINATE, jpacketHandler, arraylist); //Capture all the packets while the timeout
          
        pcap.close(); // Close jnet pcap
        
        int avg_time = Integer.parseInt(arraylist.get(arraylist.size()-1));
        System.out.println("avg time: " + avg_time);
        arraylist.remove(arraylist.size()-1);

        int tcp_size = Integer.parseInt(arraylist.get(arraylist.size()-1));
        System.out.println("tcp size: " + tcp_size);
        arraylist.remove(arraylist.size()-1);

        int udp_size = Integer.parseInt(arraylist.get(arraylist.size()-1));
        System.out.println("udp size: " + udp_size);
        arraylist.remove(arraylist.size()-1);

        int udp_counter = Integer.parseInt(arraylist.get(arraylist.size()-1));
        System.out.println("udp counter: " +udp_counter);
        arraylist.remove(arraylist.size()-1);

        int tcp_counter = Integer.parseInt(arraylist.get(arraylist.size()-1));
        System.out.println("tcp counter: " + tcp_counter);
        arraylist.remove(arraylist.size()-1);

        int counter = Integer.parseInt(arraylist.get(arraylist.size()-1));
        System.out.println("total counter: " +counter);
        arraylist.remove(arraylist.size()-1);

        int size = Integer.parseInt(arraylist.get(arraylist.size()-1));
        System.out.println("size: " +size);
        arraylist.remove(arraylist.size()-1);

        Iterator<String> itr = arraylist.iterator();
        
        String src1 = "cn_new.csv";
        CSVLoader loader = new CSVLoader();
        loader.setSource(new File(src1)); // Loading the data from current directory

        Instances dataset = loader.getDataSet();
        Instance data_cn = new DenseInstance(8);

        Attribute attribute1 = new Attribute("no_packets");
        Attribute attribute2 = new Attribute("total.size_packets");
        Attribute attribute3 = new Attribute("activity");

        data_cn.setValue(0, tcp_counter);
        data_cn.setValue(1, tcp_size);
        data_cn.setValue(2, udp_counter);
        data_cn.setValue(3, udp_size);
        data_cn.setValue(4, counter);
        data_cn.setValue(5, size);
        data_cn.setValue(6, avg_time);
        data_cn.setDataset(dataset);
        dataset.setClassIndex(7);
        Classifier ibk_test = new IBk(1);
        Evaluation validation_new = new Evaluation(dataset);
        ibk_test.buildClassifier(dataset);
        double a = ibk_test.classifyInstance(data_cn);

        if(a == 0.0){
        	System.out.println("Current activity going on is browsing HTML pages.");
        }else if(a == 1.0){
        	System.out.println("Current activity going on is browsing e-commerce websites");
        }else if(a == 2.0){
        	System.out.println("Current activity going on is watching video");
        }else{
            System.out.println("No activity is going on");
        }
    }
}  
