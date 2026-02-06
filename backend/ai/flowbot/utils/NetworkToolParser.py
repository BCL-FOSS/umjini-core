import re
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import xml.etree.ElementTree as ET

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkToolParser:
    """Parser for various network CLI tool outputs with anomaly detection"""
    
    @staticmethod
    def parse_nmap(output: str) -> Dict[str, Any]:
        """
        Parse nmap output and detect scanning patterns
        
        Returns structured data and detected anomalies
        """
        parsed = {
            "tool": "nmap",
            "raw_output": output,
            "hosts": [],
            "open_ports": [],
            "anomalies": []
        }
        
        # Extract hosts
        host_pattern = r"Nmap scan report for ([^\n]+)"
        hosts = re.findall(host_pattern, output)
        parsed["hosts"] = hosts
        
        # Extract open ports
        port_pattern = r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)"
        ports = re.findall(port_pattern, output)
        
        for port, proto, state, service in ports:
            parsed["open_ports"].append({
                "port": int(port),
                "protocol": proto,
                "state": state,
                "service": service
            })
        
        # Anomaly detection
        open_count = len([p for p in parsed["open_ports"] if p["state"] == "open"])
        
        if open_count > 20:
            parsed["anomalies"].append({
                "type": "excessive_open_ports",
                "severity": "MEDIUM",
                "description": f"Found {open_count} open ports, possible misconfiguration"
            })
        
        # Check for suspicious ports
        suspicious_ports = [23, 69, 135, 139, 445, 1433, 3306, 3389, 5900]
        for port_info in parsed["open_ports"]:
            if port_info["port"] in suspicious_ports and port_info["state"] == "open":
                parsed["anomalies"].append({
                    "type": "suspicious_port_open",
                    "severity": "HIGH",
                    "port": port_info["port"],
                    "service": port_info["service"],
                    "description": f"Potentially risky port {port_info['port']} ({port_info['service']}) is open"
                })
        
        return parsed
    
    @staticmethod
    def parse_tcpdump(output: str) -> Dict[str, Any]:
        """
        Parse tcpdump output and detect traffic anomalies
        """
        parsed = {
            "tool": "tcpdump",
            "raw_output": output,
            "packets": [],
            "statistics": {},
            "anomalies": []
        }
        
        lines = output.strip().split('\n')
        
        # Parse packet lines
        syn_count = 0
        unique_ips = set()
        port_scan_tracker = {}
        
        for line in lines:
            if not line.strip():
                continue
            
            # Extract timestamp
            timestamp_match = re.match(r'^(\d{2}:\d{2}:\d{2}\.\d+)', line)
            
            # Extract IPs
            ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            ips = re.findall(ip_pattern, line)
            
            if len(ips) >= 2:
                src_ip, dst_ip = ips[0], ips[1]
                unique_ips.update([src_ip, dst_ip])
                
                # Track potential port scanning
                if src_ip not in port_scan_tracker:
                    port_scan_tracker[src_ip] = set()
                
                # Extract destination port
                port_match = re.search(r'\.(\d+):', line)
                if port_match:
                    port_scan_tracker[src_ip].add(port_match.group(1))
            
            # Detect SYN packets (potential SYN flood)
            if 'Flags [S]' in line or '[SYN]' in line:
                syn_count += 1
            
            parsed["packets"].append({
                "timestamp": timestamp_match.group(1) if timestamp_match else None,
                "line": line
            })
        
        parsed["statistics"] = {
            "total_packets": len(parsed["packets"]),
            "unique_ips": len(unique_ips),
            "syn_packets": syn_count
        }
        
        # Anomaly detection: SYN flood
        if syn_count > 100:
            parsed["anomalies"].append({
                "type": "potential_syn_flood",
                "severity": "CRITICAL",
                "syn_count": syn_count,
                "description": f"Detected {syn_count} SYN packets, possible SYN flood attack"
            })
        
        # Anomaly detection: Port scanning
        for src_ip, ports in port_scan_tracker.items():
            if len(ports) > 50:
                parsed["anomalies"].append({
                    "type": "port_scan_detected",
                    "severity": "HIGH",
                    "source_ip": src_ip,
                    "ports_scanned": len(ports),
                    "description": f"IP {src_ip} scanned {len(ports)} different ports"
                })
        
        return parsed
    
    @staticmethod
    def parse_traceroute(output: str) -> Dict[str, Any]:
        """
        Parse traceroute output and detect routing issues
        """
        parsed = {
            "tool": "traceroute",
            "raw_output": output,
            "hops": [],
            "destination": None,
            "anomalies": []
        }
        
        lines = output.strip().split('\n')
        
        # Extract destination
        if lines:
            dest_match = re.search(r'to ([^\s]+)', lines[0])
            if dest_match:
                parsed["destination"] = dest_match.group(1)
        
        timeout_count = 0
        high_latency_count = 0
        
        for line in lines[1:]:
            if not line.strip():
                continue
            
            # Parse hop line
            hop_match = re.match(r'\s*(\d+)\s+(.+)', line)
            if hop_match:
                hop_num = int(hop_match.group(1))
                hop_data = hop_match.group(2)
                
                # Check for timeouts
                if '* * *' in hop_data:
                    timeout_count += 1
                    parsed["hops"].append({
                        "hop": hop_num,
                        "status": "timeout",
                        "latency": None
                    })
                else:
                    # Extract latency
                    latency_matches = re.findall(r'([\d.]+)\s*ms', hop_data)
                    if latency_matches:
                        avg_latency = sum(float(l) for l in latency_matches) / len(latency_matches)
                        
                        if avg_latency > 200:
                            high_latency_count += 1
                        
                        parsed["hops"].append({
                            "hop": hop_num,
                            "status": "success",
                            "latency": avg_latency,
                            "data": hop_data
                        })
        
        # Anomaly detection
        if timeout_count > 3:
            parsed["anomalies"].append({
                "type": "excessive_timeouts",
                "severity": "MEDIUM",
                "timeout_count": timeout_count,
                "description": f"Multiple timeouts detected ({timeout_count} hops)"
            })
        
        if high_latency_count > 2:
            parsed["anomalies"].append({
                "type": "high_latency_path",
                "severity": "MEDIUM",
                "description": f"High latency detected in {high_latency_count} hops (>200ms)"
            })
        
        return parsed
    
    @staticmethod
    def parse_iperf(output: str) -> Dict[str, Any]:
        """
        Parse iperf output and detect performance issues
        """
        parsed = {
            "tool": "iperf",
            "raw_output": output,
            "bandwidth": None,
            "jitter": None,
            "packet_loss": None,
            "anomalies": []
        }
        
        # Extract bandwidth
        bandwidth_match = re.search(r'(\d+\.?\d*)\s*(Mbits?|Gbits?)/sec', output)
        if bandwidth_match:
            value = float(bandwidth_match.group(1))
            unit = bandwidth_match.group(2)
            
            # Convert to Mbps
            if 'Gbit' in unit:
                value *= 1000
            
            parsed["bandwidth"] = {
                "value": value,
                "unit": "Mbps"
            }
            
            # Anomaly: Low bandwidth
            if value < 10:
                parsed["anomalies"].append({
                    "type": "low_bandwidth",
                    "severity": "HIGH",
                    "bandwidth": value,
                    "description": f"Very low bandwidth detected: {value} Mbps"
                })
        
        # Extract jitter (UDP tests)
        jitter_match = re.search(r'(\d+\.?\d*)\s*ms\s*jitter', output, re.IGNORECASE)
        if jitter_match:
            jitter = float(jitter_match.group(1))
            parsed["jitter"] = jitter
            
            if jitter > 30:
                parsed["anomalies"].append({
                    "type": "high_jitter",
                    "severity": "MEDIUM",
                    "jitter": jitter,
                    "description": f"High jitter detected: {jitter}ms (>30ms)"
                })
        
        # Extract packet loss
        loss_match = re.search(r'(\d+\.?\d*)%\s*packet loss', output, re.IGNORECASE)
        if loss_match:
            loss = float(loss_match.group(1))
            parsed["packet_loss"] = loss
            
            if loss > 5:
                parsed["anomalies"].append({
                    "type": "packet_loss",
                    "severity": "HIGH",
                    "loss_percentage": loss,
                    "description": f"Significant packet loss: {loss}%"
                })
        
        return parsed
    
    @staticmethod
    def parse_tshark(output: str) -> Dict[str, Any]:
        """
        Parse tshark output and detect protocol anomalies
        """
        parsed = {
            "tool": "tshark",
            "raw_output": output,
            "packets": [],
            "protocol_stats": {},
            "anomalies": []
        }
        
        lines = output.strip().split('\n')
        
        protocols = {}
        dns_queries = []
        http_requests = []
        
        for line in lines:
            if not line.strip():
                continue
            
            # Basic packet parsing
            parts = line.split()
            if len(parts) >= 5:
                parsed["packets"].append({
                    "line": line,
                    "parts": parts
                })
                
                # Track protocols
                if len(parts) >= 5:
                    protocol = parts[4] if len(parts) > 4 else 'unknown'
                    protocols[protocol] = protocols.get(protocol, 0) + 1
            
            # DNS tunneling detection
            if 'DNS' in line.upper():
                # Look for unusually long DNS queries
                if len(line) > 200:
                    dns_queries.append(line)
            
            # HTTP anomalies
            if 'HTTP' in line.upper():
                http_requests.append(line)
        
        parsed["protocol_stats"] = protocols
        
        # Anomaly: DNS tunneling
        if len(dns_queries) > 10:
            parsed["anomalies"].append({
                "type": "potential_dns_tunneling",
                "severity": "HIGH",
                "suspicious_queries": len(dns_queries),
                "description": f"Detected {len(dns_queries)} abnormally long DNS queries"
            })
        
        # Anomaly: Unusual protocol distribution
        total_packets = sum(protocols.values())
        for proto, count in protocols.items():
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            if proto in ['ICMP'] and percentage > 50:
                parsed["anomalies"].append({
                    "type": "unusual_protocol_distribution",
                    "severity": "MEDIUM",
                    "protocol": proto,
                    "percentage": percentage,
                    "description": f"{proto} traffic is {percentage:.1f}% of total (possible ICMP flood)"
                })
        
        return parsed
    
    @staticmethod
    def parse_pcap_summary(output: str) -> Dict[str, Any]:
        """
        Parse PCAP file summary/statistics
        """
        parsed = {
            "tool": "pcap_analysis",
            "raw_output": output,
            "statistics": {},
            "anomalies": []
        }
        
        # Extract packet count
        packet_match = re.search(r'(\d+)\s*packets', output)
        if packet_match:
            parsed["statistics"]["total_packets"] = int(packet_match.group(1))
        
        # Extract duration
        duration_match = re.search(r'(\d+\.?\d*)\s*seconds', output)
        if duration_match:
            parsed["statistics"]["duration"] = float(duration_match.group(1))
        
        # Calculate packets per second
        if "total_packets" in parsed["statistics"] and "duration" in parsed["statistics"]:
            pps = parsed["statistics"]["total_packets"] / parsed["statistics"]["duration"]
            parsed["statistics"]["packets_per_second"] = pps
            
            # Anomaly: Very high PPS (DDoS indicator)
            if pps > 10000:
                parsed["anomalies"].append({
                    "type": "high_packet_rate",
                    "severity": "CRITICAL",
                    "pps": pps,
                    "description": f"Extremely high packet rate: {pps:.0f} pps (possible DDoS)"
                })
        
        return parsed
    
    @classmethod
    def parse_tool_output(cls, tool_type: str, output: str) -> Dict[str, Any]:
        """
        Main parser dispatcher
        
        Args:
            tool_type: One of 'nmap', 'tcpdump', 'traceroute', 'iperf', 'tshark', 'pcap'
            output: Raw tool output
        
        Returns:
            Parsed and analyzed output with anomalies
        """
        parsers = {
            'nmap': cls.parse_nmap,
            'tcpdump': cls.parse_tcpdump,
            'traceroute': cls.parse_traceroute,
            'dnstraceroute': cls.parse_traceroute,  # Same format
            'iperf': cls.parse_iperf,
            'tshark': cls.parse_tshark,
            'pcap': cls.parse_pcap_summary
        }
        
        parser = parsers.get(tool_type.lower())
        
        if parser:
            try:
                result = parser(output)
                result["parsed_at"] = datetime.utcnow().isoformat()
                return result
            except Exception as e:
                logger.error(f"Error parsing {tool_type}: {e}", exc_info=True)
                return {
                    "tool": tool_type,
                    "raw_output": output,
                    "error": str(e),
                    "anomalies": []
                }
        else:
            # Generic parsing
            return {
                "tool": tool_type,
                "raw_output": output,
                "anomalies": [],
                "note": "No specific parser available, using generic parsing"
            }