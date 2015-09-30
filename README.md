# NMAPgrapher v0.1a
A tool to generate graph and other output from NMAP XML files. 

###What is it for?
This tool was primarily intended to easily digest NMAP output for inclusion in penetration testing reports as supplementary information, however feel free to use it as you wish.

###What does it do?
NMAP grapher is currently capable of generating the following outputs:
  - Most and Least Common Services
  - Most and Least Common Ports
  - Most and Least Common Operating Systems
  - Hosts with Most and Least number of open ports
  - HTML document with tables including each host and open services / ports

The following output formats are supported:
  - PNG
  - SVG
  - HTML
  - CSV

###Where can I find a complete usage guide?
Usage information can be found at http://www.attactics.org/2015/09/nmapgrapher-tool-for-digesting-nmap-xml.html
Even more usage information can be found by running NMapgrapher.py -h

###Your code sucks and it's broken
I'm not a python ninja and the tool is in alpha, so that is quite possible. Feel free to contact me on twitter (@evasiv3) and I can fix any bugs or issues you are experiencing.
