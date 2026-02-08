/**
 * Network Visualization Module
 * Add this script section after the existing scripts in probes.html
 */

// Network visualization instances for each tab
const networkVisualizers = {
  trace: null,
  perf: null,
  scan: null,
  pcap: null
};

// Data sets for vis-network
const networkDataSets = {
  trace: { nodes: new vis.DataSet([]), edges: new vis.DataSet([]) },
  perf: { nodes: new vis.DataSet([]), edges: new vis.DataSet([]) },
  scan: { nodes: new vis.DataSet([]), edges: new vis.DataSet([]) },
  pcap: { nodes: new vis.DataSet([]), edges: new vis.DataSet([]) }
};

// Common vis-network options
const getNetworkOptions = (type) => ({
  nodes: {
    shape: 'box',
    font: { size: 14 },
    borderWidth: 2,
    shadow: true
  },
  edges: {
    arrows: { to: { enabled: true, scaleFactor: 0.5 } },
    smooth: { type: 'cubicBezier' },
    width: 2
  },
  physics: {
    enabled: type === 'scan',
    hierarchicalRepulsion: {
      nodeDistance: 150,
      centralGravity: 0.3
    },
    solver: type === 'scan' ? "hierarchicalRepulsion" : "barnesHut"
  },
  layout: type === 'trace' || type === 'perf' ? {
    hierarchical: {
      direction: 'LR',
      sortMethod: 'directed',
      levelSeparation: 200
    }
  } : {},
  interaction: {
    hover: true,
    tooltipDelay: 100,
    navigationButtons: true
  }
});

// Initialize network visualizer for a specific type
function initializeNetwork(type, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return null;

  const data = {
    nodes: networkDataSets[type].nodes,
    edges: networkDataSets[type].edges
  };

  const options = getNetworkOptions(type);
  const network = new vis.Network(container, data, options);

  // Add click event for node details
  network.on("click", function(params) {
    if (params.nodes.length > 0) {
      const nodeId = params.nodes[0];
      const node = networkDataSets[type].nodes.get(nodeId);
      showNodeDetails(node);
    }
  });

  return network;
}

// Show node details in notification modal
function showNodeDetails(node) {
  if (!node) return;
  
  document.getElementById('notificationModalLabel').textContent = 'Node Details';
  document.getElementById('notif-modal-text').innerHTML = `
    <strong>Label:</strong> ${node.label || 'N/A'}<br>
    <strong>Title:</strong> ${node.title || 'N/A'}<br>
    ${node.ip ? `<strong>IP:</strong> ${node.ip}<br>` : ''}
    ${node.latency ? `<strong>Latency:</strong> ${node.latency}<br>` : ''}
    ${node.bandwidth ? `<strong>Bandwidth:</strong> ${node.bandwidth}<br>` : ''}
  `;
  notificationModal.show();
}

// Parse and visualize traceroute results
async function visualizeTraceroute(data) {
  networkDataSets.trace.nodes.clear();
  networkDataSets.trace.edges.clear();

  if (!data || !data.hops) {
    showAlert('trace-alerts', 'No traceroute data available', 'warning');
    return;
  }

  const hops = data.hops;
  let previousHop = null;

  // Add source node
  networkDataSets.trace.nodes.add({
    id: 'source',
    label: 'Source\n' + (data.source || 'Local'),
    color: { background: '#90EE90', border: '#006400' },
    shape: 'diamond',
    title: `Source: ${data.source || 'Local Probe'}`
  });

  previousHop = 'source';

  // Add hop nodes
  hops.forEach((hop, index) => {
    const hopId = `hop-${index}`;
    const ip = hop.ip || hop.host || '***';
    const latency = hop.rtt || hop.latency || 'N/A';
    
    networkDataSets.trace.nodes.add({
      id: hopId,
      label: `Hop ${index + 1}\n${ip}\n${latency}ms`,
      color: { 
        background: ip === '***' ? '#FFB6C1' : '#87CEEB',
        border: ip === '***' ? '#FF0000' : '#0000FF'
      },
      title: `Hop: ${index + 1}<br>IP: ${ip}<br>Latency: ${latency}ms<br>Hostname: ${hop.hostname || 'Unknown'}`,
      latency: latency
    });

    networkDataSets.trace.edges.add({
      from: previousHop,
      to: hopId,
      label: `${latency}ms`,
      color: { color: ip === '***' ? '#FF0000' : '#0000FF' }
    });

    previousHop = hopId;
  });

  // Add destination node
  networkDataSets.trace.nodes.add({
    id: 'destination',
    label: 'Destination\n' + (data.destination || 'Target'),
    color: { background: '#FFD700', border: '#FF8C00' },
    shape: 'star',
    title: `Destination: ${data.destination || 'Target'}`
  });

  networkDataSets.trace.edges.add({
    from: previousHop,
    to: 'destination',
    color: { color: '#00FF00' }
  });

  if (!networkVisualizers.trace) {
    networkVisualizers.trace = initializeNetwork('trace', 'network-trace');
  }
}

// Parse and visualize performance test results
async function visualizePerformanceTest(data) {
  networkDataSets.perf.nodes.clear();
  networkDataSets.perf.edges.clear();

  if (!data) {
    showAlert('perf-alerts', 'No performance test data available', 'warning');
    return;
  }

  const isServer = data.mode === 'server';
  const bandwidth = data.bandwidth || 'N/A';
  const jitter = data.jitter || 'N/A';
  const packetLoss = data.packet_loss || '0%';

  // Add client node
  networkDataSets.perf.nodes.add({
    id: 'client',
    label: `Client\n${data.client_ip || 'Unknown'}`,
    color: { background: '#87CEEB', border: '#0000FF' },
    shape: 'box',
    title: `Client: ${data.client_ip || 'Unknown'}<br>Port: ${data.client_port || 'N/A'}`
  });

  // Add server node
  networkDataSets.perf.nodes.add({
    id: 'server',
    label: `Server\n${data.server_ip || 'Unknown'}`,
    color: { background: '#90EE90', border: '#006400' },
    shape: 'box',
    title: `Server: ${data.server_ip || 'Unknown'}<br>Port: ${data.server_port || 'N/A'}`
  });

  // Add edge with performance metrics
  networkDataSets.perf.edges.add({
    from: 'client',
    to: 'server',
    label: `${bandwidth}\nJitter: ${jitter}\nLoss: ${packetLoss}`,
    color: { color: '#00FF00' },
    width: 4,
    title: `Bandwidth: ${bandwidth}<br>Jitter: ${jitter}<br>Packet Loss: ${packetLoss}`,
    bandwidth: bandwidth
  });

  // Add metrics node
  networkDataSets.perf.nodes.add({
    id: 'metrics',
    label: `Metrics\nBandwidth: ${bandwidth}\nJitter: ${jitter}\nLoss: ${packetLoss}`,
    color: { background: '#FFD700', border: '#FF8C00' },
    shape: 'ellipse',
    x: 0,
    y: -200,
    fixed: true
  });

  if (!networkVisualizers.perf) {
    networkVisualizers.perf = initializeNetwork('perf', 'network-perf');
  }
}

// Parse and visualize network scan results (from previous implementation)
async function visualizeNetworkScan(data) {
  networkDataSets.scan.nodes.clear();
  networkDataSets.scan.edges.clear();

  if (!data || !data.nmaprun || !data.nmaprun.host) {
    showAlert('scan-alerts', 'No scan data available', 'warning');
    return;
  }

  const devices = parseNmapJson(data);
  const deviceArray = Object.values(devices);

  // Create nodes
  deviceArray.forEach(dev => {
    const nodeLabel = `${icons[dev.role]} ${dev.vendor}\n${dev.ip}\n${dev.hostname}`;
    const nodeTitle = `
      <b>Device Information</b><br/>
      MAC: ${dev.mac}<br/>
      IP: ${dev.ip}<br/>
      Hostname: ${dev.hostname}<br/>
      Vendor: ${dev.vendor}<br/>
      OS: ${dev.os} (${dev.os_accuracy}% confidence)<br/>
      Role: ${dev.role}<br/>
      Open Ports: ${dev.open_ports}<br/>
      Services: ${dev.services || 'none'}
    `;

    networkDataSets.scan.nodes.add({
      id: dev.mac,
      label: nodeLabel,
      title: nodeTitle,
      group: dev.role,
      shape: 'box',
      ip: dev.ip
    });
  });

  // Create edges based on network topology
  const firewalls = deviceArray.filter(d => d.role === 'firewall');
  const switches = deviceArray.filter(d => d.role === 'switch');
  const servers = deviceArray.filter(d => d.role === 'server');
  const endpoints = deviceArray.filter(d => d.role === 'endpoint');

  firewalls.forEach(fw => {
    switches.forEach(sw => {
      networkDataSets.scan.edges.add({
        from: fw.mac,
        to: sw.mac,
        width: 3,
        color: { color: '#ff6961' }
      });
    });
  });

  switches.forEach(sw => {
    [...servers, ...endpoints].forEach(device => {
      networkDataSets.scan.edges.add({
        from: sw.mac,
        to: device.mac,
        dashes: device.role === 'endpoint'
      });
    });
  });

  if (!networkVisualizers.scan) {
    networkVisualizers.scan = initializeNetwork('scan', 'network-scan');
  }

  detectNetworkAlerts(deviceArray, 'scan-alerts');
}

// Parse and visualize packet capture results
async function visualizePacketCapture(data) {
  networkDataSets.pcap.nodes.clear();
  networkDataSets.pcap.edges.clear();

  if (!data || !data.packets) {
    showAlert('pcap-alerts', 'No packet capture data available', 'warning');
    return;
  }

  const packets = data.packets;
  const connectionMap = new Map();
  const nodeMap = new Map();

  // Analyze packets and build connection map
  packets.forEach(packet => {
    const src = packet.src_ip;
    const dst = packet.dst_ip;
    const protocol = packet.protocol || 'Unknown';
    const size = packet.size || 0;

    // Add nodes
    if (!nodeMap.has(src)) {
      nodeMap.set(src, {
        id: src,
        label: src,
        packetsSent: 0,
        packetsReceived: 0,
        bytesSent: 0,
        bytesReceived: 0
      });
    }
    if (!nodeMap.has(dst)) {
      nodeMap.set(dst, {
        id: dst,
        label: dst,
        packetsSent: 0,
        packetsReceived: 0,
        bytesSent: 0,
        bytesReceived: 0
      });
    }

    // Update node stats
    const srcNode = nodeMap.get(src);
    const dstNode = nodeMap.get(dst);
    srcNode.packetsSent++;
    srcNode.bytesSent += size;
    dstNode.packetsReceived++;
    dstNode.bytesReceived += size;

    // Track connections
    const connKey = `${src}-${dst}`;
    if (!connectionMap.has(connKey)) {
      connectionMap.set(connKey, {
        from: src,
        to: dst,
        packets: 0,
        bytes: 0,
        protocols: new Set()
      });
    }
    const conn = connectionMap.get(connKey);
    conn.packets++;
    conn.bytes += size;
    conn.protocols.add(protocol);
  });

  // Add nodes to visualization
  nodeMap.forEach(node => {
    const totalPackets = node.packetsSent + node.packetsReceived;
    const totalBytes = node.bytesSent + node.bytesReceived;

    networkDataSets.pcap.nodes.add({
      id: node.id,
      label: `${node.label}\n${totalPackets} pkts`,
      title: `IP: ${node.id}<br>Sent: ${node.packetsSent} packets (${formatBytes(node.bytesSent)})<br>Received: ${node.packetsReceived} packets (${formatBytes(node.bytesReceived)})`,
      color: {
        background: node.packetsSent > node.packetsReceived ? '#87CEEB' : '#90EE90',
        border: '#000000'
      },
      value: totalPackets
    });
  });

  // Add edges to visualization
  connectionMap.forEach(conn => {
    const protocols = Array.from(conn.protocols).join(', ');
    networkDataSets.pcap.edges.add({
      from: conn.from,
      to: conn.to,
      label: `${conn.packets} pkts\n${protocols}`,
      title: `Packets: ${conn.packets}<br>Bytes: ${formatBytes(conn.bytes)}<br>Protocols: ${protocols}`,
      value: conn.packets,
      color: { color: getProtocolColor(conn.protocols) }
    });
  });

  if (!networkVisualizers.pcap) {
    networkVisualizers.pcap = initializeNetwork('pcap', 'network-pcap');
  }
}

// Helper function to format bytes
function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Helper function to get protocol color
function getProtocolColor(protocols) {
  if (protocols.has('TCP')) return '#0000FF';
  if (protocols.has('UDP')) return '#00FF00';
  if (protocols.has('ICMP')) return '#FF0000';
  return '#808080';
}

// Show alert messages
function showAlert(containerId, message, type = 'info') {
  const alertDiv = document.getElementById(containerId);
  if (!alertDiv) return;

  const alertClass = type === 'warning' ? 'alert-warning' : type === 'error' ? 'alert-danger' : 'alert-info';
  alertDiv.innerHTML = `<div class="alert ${alertClass} alert-dismissible fade show" role="alert">
    ${message}
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
  </div>`;
}

// Detect network alerts for scan results
function detectNetworkAlerts(devices, alertContainerId) {
  const alerts = [];
  
  const uplinks = devices.filter(d => d.role === 'switch' || d.role === 'firewall').length;
  if (uplinks < 2) {
    alerts.push('⚠️ Possible missing uplinks detected!');
  }

  const orphans = devices.filter(d => {
    return !networkDataSets.scan.edges.get().some(e => e.from === d.mac || e.to === d.mac);
  });

  if (orphans.length > 0) {
    alerts.push(`⚠️ ${orphans.length} orphaned devices found`);
  }

  if (alerts.length > 0) {
    showAlert(alertContainerId, alerts.join('<br>'), 'warning');
  }
}