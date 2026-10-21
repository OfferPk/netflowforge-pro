/\*\*  
 \* NetFlowForge Pro \- RFC 7011 IPFIX & RFC 3954 NetFlow v9 Telemetry Engine  
 \* Models Message Headers, Template FlowSets, Data FlowSets, Sampling Math,  
 \* and Switch Hardware Flow Table TCAM Sizing.  
 \*/

(function (root, factory) {  
  if (typeof define \=== 'function' && define.amd) {  
    define(\[\], factory);  
  } else if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.NetFlowEngine \= factory();  
  }  
}(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  // Helper: Parse IPv4 string to 4-byte array  
  function parseIPv4(ipStr) {  
    if (\!ipStr || typeof ipStr \!== 'string') return \[0, 0, 0, 0\];  
    var parts \= ipStr.trim().split('.');  
    var bytes \= \[\];  
    for (var i \= 0; i \< 4; i++) {  
      var n \= parseInt(parts\[i\], 10);  
      bytes.push(isNaN(n) ? 0 : Math.max(0, Math.min(255, n)));  
    }  
    return bytes;  
  }

  // Standard IANA IPFIX Information Elements (RFC 7012\)  
  var IANA\_ELEMENTS \= {  
    octetDeltaCount: { id: 1, length: 4, name: 'octetDeltaCount' },  
    packetDeltaCount: { id: 2, length: 4, name: 'packetDeltaCount' },  
    protocolIdentifier: { id: 4, length: 1, name: 'protocolIdentifier' },  
    ipClassOfService: { id: 5, length: 1, name: 'ipClassOfService' },  
    tcpControlBits: { id: 6, length: 1, name: 'tcpControlBits' },  
    sourceTransportPort: { id: 7, length: 2, name: 'sourceTransportPort' },  
    sourceIPv4Address: { id: 8, length: 4, name: 'sourceIPv4Address' },  
    ipV4PrefixLength: { id: 9, length: 1, name: 'ipV4PrefixLength' },  
    ingressInterface: { id: 10, length: 4, name: 'ingressInterface' },  
    destinationTransportPort: { id: 11, length: 2, name: 'destinationTransportPort' },  
    destinationIPv4Address: { id: 12, length: 4, name: 'destinationIPv4Address' },  
    egressInterface: { id: 14, length: 4, name: 'egressInterface' },  
    bgpSourceAsNumber: { id: 16, length: 4, name: 'bgpSourceAsNumber' },  
    bgpDestinationAsNumber: { id: 17, length: 4, name: 'bgpDestinationAsNumber' },  
    flowStartSysUpTime: { id: 22, length: 4, name: 'flowStartSysUpTime' },  
    flowEndSysUpTime: { id: 21, length: 4, name: 'flowEndSysUpTime' }  
  };

  // Build IPFIX Message (RFC 7011\)  
  function buildIPFIXMessage(params) {  
    params \= params || {};  
    var version \= params.version \=== 'v9' ? 0x0009 : 0x000a; // 10 for IPFIX, 9 for NetFlow v9  
    var domainId \= params.observationDomainId \!== undefined ? params.observationDomainId : 1;  
    var seqNumber \= params.sequenceNumber \!== undefined ? params.sequenceNumber : 101;  
    var exportTime \= params.exportTime \!== undefined ? params.exportTime : Math.floor(Date.now() / 1000);  
    var templateId \= params.templateId || 256;

    // Selected fields list  
    var fieldKeys \= params.selectedFields || \[  
      'sourceIPv4Address',  
      'destinationIPv4Address',  
      'protocolIdentifier',  
      'sourceTransportPort',  
      'destinationTransportPort',  
      'tcpControlBits',  
      'packetDeltaCount',  
      'octetDeltaCount',  
      'ingressInterface',  
      'egressInterface'  
    \];

    // 1\. Construct Template FlowSet  
    var templateSetId \= version \=== 0x0009 ? 0 : 2; // Set ID 2 for IPFIX Template, 0 for NetFlow v9  
    var templateRecordsBytes \= \[\];  
    // Template ID (16 bits)  
    templateRecordsBytes.push((templateId \>\> 8\) & 0xff);  
    templateRecordsBytes.push(templateId & 0xff);  
    // Field Count (16 bits)  
    templateRecordsBytes.push((fieldKeys.length \>\> 8\) & 0xff);  
    templateRecordsBytes.push(fieldKeys.length & 0xff);

    var totalRecordDataLen \= 0;  
    for (var i \= 0; i \< fieldKeys.length; i++) {  
      var elem \= IANA\_ELEMENTS\[fieldKeys\[i\]\] || { id: 1, length: 4 };  
      templateRecordsBytes.push((elem.id \>\> 8\) & 0xff);  
      templateRecordsBytes.push(elem.id & 0xff);  
      templateRecordsBytes.push((elem.length \>\> 8\) & 0xff);  
      templateRecordsBytes.push(elem.length & 0xff);  
      totalRecordDataLen \+= elem.length;  
    }

    var templateSetLen \= 4 \+ templateRecordsBytes.length; // 4B set header (Set ID \+ Length)  
    var templateFlowSet \= \[\];  
    templateFlowSet.push((templateSetId \>\> 8\) & 0xff);  
    templateFlowSet.push(templateSetId & 0xff);  
    templateFlowSet.push((templateSetLen \>\> 8\) & 0xff);  
    templateFlowSet.push(templateSetLen & 0xff);  
    templateFlowSet \= templateFlowSet.concat(templateRecordsBytes);

    // 2\. Construct Data FlowSet (Sample Record)  
    var dataRecordsBytes \= \[\];  
    var srcIpBytes \= parseIPv4(params.sampleSrcIp || '198.51.100.42');  
    var dstIpBytes \= parseIPv4(params.sampleDstIp || '203.0.113.10');  
    var srcPort \= params.sampleSrcPort || 53412;  
    var dstPort \= params.sampleDstPort || 443;  
    var proto \= params.sampleProtocol \!== undefined ? params.sampleProtocol : 6; // TCP  
    var tcpFlags \= params.sampleTcpFlags \!== undefined ? params.sampleTcpFlags : 0x18; // ACK \+ PSH  
    var packets \= params.samplePackets || 1240;  
    var octets \= params.sampleOctets || 184520;

    for (var k \= 0; k \< fieldKeys.length; k++) {  
      var fName \= fieldKeys\[k\];  
      if (fName \=== 'sourceIPv4Address') dataRecordsBytes \= dataRecordsBytes.concat(srcIpBytes);  
      else if (fName \=== 'destinationIPv4Address') dataRecordsBytes \= dataRecordsBytes.concat(dstIpBytes);  
      else if (fName \=== 'protocolIdentifier') dataRecordsBytes.push(proto & 0xff);  
      else if (fName \=== 'ipClassOfService') dataRecordsBytes.push(0x00);  
      else if (fName \=== 'tcpControlBits') dataRecordsBytes.push(tcpFlags & 0xff);  
      else if (fName \=== 'sourceTransportPort') {  
        dataRecordsBytes.push((srcPort \>\> 8\) & 0xff);  
        dataRecordsBytes.push(srcPort & 0xff);  
      } else if (fName \=== 'destinationTransportPort') {  
        dataRecordsBytes.push((dstPort \>\> 8\) & 0xff);  
        dataRecordsBytes.push(dstPort & 0xff);  
      } else if (fName \=== 'packetDeltaCount') {  
        dataRecordsBytes.push((packets \>\> 24\) & 0xff);  
        dataRecordsBytes.push((packets \>\> 16\) & 0xff);  
        dataRecordsBytes.push((packets \>\> 8\) & 0xff);  
        dataRecordsBytes.push(packets & 0xff);  
      } else if (fName \=== 'octetDeltaCount') {  
        dataRecordsBytes.push((octets \>\> 24\) & 0xff);  
        dataRecordsBytes.push((octets \>\> 16\) & 0xff);  
        dataRecordsBytes.push((octets \>\> 8\) & 0xff);  
        dataRecordsBytes.push(octets & 0xff);  
      } else if (fName \=== 'ingressInterface') {  
        dataRecordsBytes \= dataRecordsBytes.concat(\[0x00, 0x00, 0x00, 0x02\]); // ifIndex 2  
      } else if (fName \=== 'egressInterface') {  
        dataRecordsBytes \= dataRecordsBytes.concat(\[0x00, 0x00, 0x00, 0x05\]); // ifIndex 5  
      } else if (fName \=== 'bgpSourceAsNumber') {  
        var asSrc \= params.sampleBgpSrcAs || 65001;  
        dataRecordsBytes.push((asSrc \>\> 24\) & 0xff);  
        dataRecordsBytes.push((asSrc \>\> 16\) & 0xff);  
        dataRecordsBytes.push((asSrc \>\> 8\) & 0xff);  
        dataRecordsBytes.push(asSrc & 0xff);  
      } else if (fName \=== 'bgpDestinationAsNumber') {  
        var asDst \= params.sampleBgpDstAs || 13335;  
        dataRecordsBytes.push((asDst \>\> 24\) & 0xff);  
        dataRecordsBytes.push((asDst \>\> 16\) & 0xff);  
        dataRecordsBytes.push((asDst \>\> 8\) & 0xff);  
        dataRecordsBytes.push(asDst & 0xff);  
      } else {  
        // default 4B zero  
        dataRecordsBytes \= dataRecordsBytes.concat(\[0x00, 0x00, 0x00, 0x00\]);  
      }  
    }

    // IPFIX sets must be 4-byte padded if needed  
    var pad \= (4 \- (dataRecordsBytes.length % 4)) % 4;  
    for (var p \= 0; p \< pad; p++) dataRecordsBytes.push(0x00);

    var dataSetLen \= 4 \+ dataRecordsBytes.length;  
    var dataFlowSet \= \[\];  
    dataFlowSet.push((templateId \>\> 8\) & 0xff);  
    dataFlowSet.push(templateId & 0xff);  
    dataFlowSet.push((dataSetLen \>\> 8\) & 0xff);  
    dataFlowSet.push(dataSetLen & 0xff);  
    dataFlowSet \= dataFlowSet.concat(dataRecordsBytes);

    // 3\. Message Header (16 Bytes)  
    var totalMsgLen \= 16 \+ templateFlowSet.length \+ dataFlowSet.length;  
    var msgHeader \= \[\];  
    msgHeader.push((version \>\> 8\) & 0xff);  
    msgHeader.push(version & 0xff);

    if (version \=== 0x000a) {  
      // IPFIX Header (RFC 7011): Version (2), Length (2), ExportTime (4), SeqNo (4), DomainID (4)  
      msgHeader.push((totalMsgLen \>\> 8\) & 0xff);  
      msgHeader.push(totalMsgLen & 0xff);  
      msgHeader.push((exportTime \>\> 24\) & 0xff);  
      msgHeader.push((exportTime \>\> 16\) & 0xff);  
      msgHeader.push((exportTime \>\> 8\) & 0xff);  
      msgHeader.push(exportTime & 0xff);  
      msgHeader.push((seqNumber \>\> 24\) & 0xff);  
      msgHeader.push((seqNumber \>\> 16\) & 0xff);  
      msgHeader.push((seqNumber \>\> 8\) & 0xff);  
      msgHeader.push(seqNumber & 0xff);  
      msgHeader.push((domainId \>\> 24\) & 0xff);  
      msgHeader.push((domainId \>\> 16\) & 0xff);  
      msgHeader.push((domainId \>\> 8\) & 0xff);  
      msgHeader.push(domainId & 0xff);  
    } else {  
      // NetFlow v9 Header (RFC 3954): Version (2), Count (2), SysUpTime (4), UnixSecs (4), PackageSeq (4), SourceID (4)  
      var recordCount \= 2; // 1 template \+ 1 data record  
      msgHeader.push((recordCount \>\> 8\) & 0xff);  
      msgHeader.push(recordCount & 0xff);  
      var sysUptimeMs \= 1849201;  
      msgHeader.push((sysUptimeMs \>\> 24\) & 0xff);  
      msgHeader.push((sysUptimeMs \>\> 16\) & 0xff);  
      msgHeader.push((sysUptimeMs \>\> 8\) & 0xff);  
      msgHeader.push(sysUptimeMs & 0xff);  
      msgHeader.push((exportTime \>\> 24\) & 0xff);  
      msgHeader.push((exportTime \>\> 16\) & 0xff);  
      msgHeader.push((exportTime \>\> 8\) & 0xff);  
      msgHeader.push(exportTime & 0xff);  
      msgHeader.push((seqNumber \>\> 24\) & 0xff);  
      msgHeader.push((seqNumber \>\> 16\) & 0xff);  
      msgHeader.push((seqNumber \>\> 8\) & 0xff);  
      msgHeader.push(seqNumber & 0xff);  
      msgHeader.push((domainId \>\> 24\) & 0xff);  
      msgHeader.push((domainId \>\> 16\) & 0xff);  
      msgHeader.push((domainId \>\> 8\) & 0xff);  
      msgHeader.push(domainId & 0xff);  
    }

    var fullBytes \= msgHeader.concat(templateFlowSet).concat(dataFlowSet);

    return {  
      bytes: fullBytes,  
      version: version \=== 0x000a ? 'IPFIX (RFC 7011)' : 'NetFlow v9 (RFC 3954)',  
      headerLen: msgHeader.length,  
      templateSetLen: templateFlowSet.length,  
      dataSetLen: dataFlowSet.length,  
      fieldsCount: fieldKeys.length,  
      totalRecordDataLen: totalRecordDataLen,  
      totalLength: fullBytes.length  
    };  
  }

  // Calculate Flow Sampling, Bandwidth & TCAM Table Pressure  
  function computeFlowSizing(params) {  
    params \= params || {};  
    var linkSpeedGbps \= parseFloat(params.linkSpeedGbps) || 10;  
    var samplingRate \= parseInt(params.samplingRate, 10\) || 1000; // 1 out of N  
    var activeTimeoutSec \= parseInt(params.activeTimeoutSec, 10\) || 30;  
    var inactiveTimeoutSec \= parseInt(params.inactiveTimeoutSec, 10\) || 15;  
    var avgPacketSizeBytes \= parseInt(params.avgPacketSizeBytes, 10\) || 800;  
    var tcamCapacityFlows \= parseInt(params.tcamCapacityFlows, 10\) || 131072; // Typical 128k entries

    // Total packets per second at line rate:  
    // (linkSpeed in bps) / (avgPacketSize \* 8\)  
    var lineRatePps \= (linkSpeedGbps \* 1e9) / (avgPacketSizeBytes \* 8);

    // Sampled packets / flows per second  
    var sampledPps \= lineRatePps / (samplingRate || 1);

    // Average flow lifetime (estimated based on active timeout and inactive timeout)  
    var effectiveFlowLifetime \= Math.min(activeTimeoutSec, inactiveTimeoutSec \* 2);

    // Concurrent active flows in switch memory TCAM:  
    var estimatedActiveFlows \= Math.round(sampledPps \* effectiveFlowLifetime);

    // Telemetry export bandwidth (approx 64 bytes per flow record)  
    var exportBps \= sampledPps \* 64 \* 8;  
    var exportMbps \= exportBps / 1e6;

    // TCAM table utilization  
    var tcamUtilizationPct \= Math.round((estimatedActiveFlows / tcamCapacityFlows) \* 100);

    var status \= 'SAFE';  
    var statusMessage \= 'Flow generation rate and TCAM footprint are within safe hardware limits.';

    if (tcamUtilizationPct \>= 100\) {  
      status \= 'OVERFLOW';  
      statusMessage \= 'CRITICAL TCAM OVERFLOW: Active flows (' \+ estimatedActiveFlows.toLocaleString() \+  
        ') exceed switch table capacity (' \+ tcamCapacityFlows.toLocaleString() \+ ')\! Flows will be dropped.';  
    } else if (tcamUtilizationPct \>= 75\) {  
      status \= 'PRESSURE';  
      statusMessage \= 'WARNING: High TCAM utilization (' \+ tcamUtilizationPct \+ '%). Risk of flow cache drop during microbursts.';  
    }

    return {  
      linkSpeedGbps: linkSpeedGbps,  
      samplingRate: samplingRate,  
      lineRatePps: Math.round(lineRatePps),  
      sampledPps: Math.round(sampledPps),  
      estimatedActiveFlows: estimatedActiveFlows,  
      tcamCapacityFlows: tcamCapacityFlows,  
      tcamUtilizationPct: tcamUtilizationPct,  
      exportMbps: parseFloat(exportMbps.toFixed(2)),  
      status: status,  
      statusMessage: statusMessage  
    };  
  }

  // Format bytes into Wireshark / hexdump format  
  function formatHexDump(bytes) {  
    var lines \= \[\];  
    for (var i \= 0; i \< bytes.length; i \+= 16\) {  
      var chunk \= bytes.slice(i, i \+ 16);  
      var offsetHex \= ('0000' \+ i.toString(16)).slice(-4);  
      var hexParts \= \[\];  
      var asciiParts \= \[\];

      for (var j \= 0; j \< 16; j++) {  
        if (j \< chunk.length) {  
          var b \= chunk\[j\];  
          hexParts.push(('0' \+ b.toString(16)).slice(-2));  
          asciiParts.push((b \>= 32 && b \<= 126\) ? String.fromCharCode(b) : '.');  
        } else {  
          hexParts.push('  ');  
          asciiParts.push(' ');  
        }  
      }

      var hexFormatted \= hexParts.slice(0, 8).join(' ') \+ '  ' \+ hexParts.slice(8).join(' ');  
      lines.push(offsetHex \+ ':  ' \+ hexFormatted \+ '  |' \+ asciiParts.join('') \+ '|');  
    }  
    return lines.join('\\n');  
  }

  return {  
    IANA\_ELEMENTS: IANA\_ELEMENTS,  
    parseIPv4: parseIPv4,  
    buildIPFIXMessage: buildIPFIXMessage,  
    computeFlowSizing: computeFlowSizing,  
    formatHexDump: formatHexDump  
  };  
}));  
