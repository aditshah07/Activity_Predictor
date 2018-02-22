OS Requirements:
Used Ubuntu VM. Following steps need to be performed on the Ubuntu machine:
1.) Create a root user if it doesn’t exist.
2.) Give eclipse a root access because it needs to monitor the network activity which requires root access.
3.) I open my eclipse using command- gksu eclipse.
4.) Once this is done open eclipse you can run code in the below mentioned way.

Method to create test environment:
1.) Create new java project in eclipse.
2.) Import the provided jar files (in library folder) and Add jnetpcap's jar file and                                                     native library directory path to project's build path.
3.) Import PacketSniffer.java in the project.
4.) Import the provided trained data cn_new.csv.
5.) Run the program PacketSniffer.java and follow the steps for testing it.
