/\*\*  
 \* NetFlowForge Pro \- 10-Point Zero-Trust Flow Telemetry Security Auditor  
 \* Evaluates RFC 7011 / RFC 3954 compliance, active/inactive timeouts,  
 \* template refresh intervals, TCAM flood resilience, and security field coverage.  
 \*/

(function (root, factory) {  
  if (typeof define \=== 'function' && define.amd) {  
    define(\[\], factory);  
  } else if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.NetFlowSecurityAuditor \= factory();  
  }  
}(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  function auditFlowConfiguration(config) {  
    config \= config || {};  
    var findings \= \[\];  
    var score \= 0;

    // Check 1: Template Refresh Interval  
    var tmplRefreshSec \= parseInt(config.templateRefreshSec, 10\) || 0;  
    var tmplRefreshPkts \= parseInt(config.templateRefreshPackets, 10\) || 0;  
    var check1 \= {  
      id: 'TEMPLATE\_HYGIENE',  
      name: 'Template Refresh & Decoder Sync',  
      weight: 10,  
      points: 0,  
      status: 'FAIL',  
      description: ''  
    };  
    if (tmplRefreshSec \> 0 && tmplRefreshSec \<= 60\) {  
      check1.points \= 10;  
      check1.status \= 'PASS';  
      check1.description \= 'Optimal template refresh timer (' \+ tmplRefreshSec \+ 's) guarantees collector decoder resilience.';  
    } else if (tmplRefreshSec \> 60 && tmplRefreshSec \<= 300\) {  
      check1.points \= 6;  
      check1.status \= 'WARN';  
      check1.description \= 'High template refresh timer (' \+ tmplRefreshSec \+ 's). UDP packet loss risks prolonged collector decode failures.';  
    } else {  
      check1.points \= 0;  
      check1.status \= 'FAIL';  
      check1.description \= 'CRITICAL: Template refresh missing or excessive (\>300s). Collectors will experience Unknown Template ID drops.';  
    }  
    score \+= check1.points;  
    findings.push(check1);

    // Check 2: Active Flow Timeout Tuning  
    var activeTimeout \= parseInt(config.activeTimeoutSec, 10\) || 0;  
    var check2 \= {  
      id: 'ACTIVE\_TIMEOUT',  
      name: 'Active Flow Timeout Calibration',  
      weight: 10,  
      points: 0,  
      status: 'FAIL',  
      description: ''  
    };  
    if (activeTimeout \> 0 && activeTimeout \<= 60\) {  
      check2.points \= 10;  
      check2.status \= 'PASS';  
      check2.description \= 'Active timeout (' \+ activeTimeout \+ 's) provides near real-time visibility into long-running elephant flows and DDoS.';  
    } else if (activeTimeout \> 60 && activeTimeout \<= 300\) {  
      check2.points \= 5;  
      check2.status \= 'WARN';  
      check2.description \= 'Active timeout (' \+ activeTimeout \+ 's) introduces multi-minute reporting delay for ongoing volumetric attacks.';  
    } else {  
      check2.points \= 0;  
      check2.status \= 'FAIL';  
      check2.description \= 'CRITICAL: Active timeout excessive (' \+ activeTimeout \+ 's). Long-lived flows remain invisible until termination\!';  
    }  
    score \+= check2.points;  
    findings.push(check2);

    // Check 3: Inactive Flow Timeout Tuning  
    var inactiveTimeout \= parseInt(config.inactiveTimeoutSec, 10\) || 0;  
    var check3 \= {  
      id: 'INACTIVE\_TIMEOUT',  
      name: 'Inactive Flow Timeout & TCAM Flushing',  
      weight: 10,  
      points: 0,  
      status: 'FAIL',  
      description: ''  
    };  
    if (inactiveTimeout \> 0 && inactiveTimeout \<= 15\) {  
      check3.points \= 10;  
      check3.status \= 'PASS';  
      check3.description \= 'Inactive timeout (' \+ inactiveTimeout \+ 's) rapidly evicts completed flows, freeing switch hardware TCAM.';  
    } else if (inactiveTimeout \> 15 && inactiveTimeout \<= 30\) {  
      check3.points \= 6;  
      check3.status \= 'WARN';  
      check3.description \= 'Moderate inactive timeout (' \+ inactiveTimeout \+ 's). TCAM tables may experience pressure under port scanning.';  
    } else {  
      check3.points \= 0;  
      check3.status \= 'FAIL';  
      check3.description \= 'CRITICAL: Inactive timeout too high (' \+ inactiveTimeout \+ 's). Switch memory at risk of table exhaustion.';  
    }  
    score \+= check3.points;  
    findings.push(check3);

    // Check 4: Sampling Ratio Calibration  
    var samplingRate \= parseInt(config.samplingRate, 10\) || 1;  
    var check4 \= {  
      id: 'SAMPLING\_CALIBRATION',  
      name: 'Deterministic Sampling Ratio Calibration',  
      weight: 10,  
      points: 0,  
      status: 'FAIL',  
      description: ''  
    };  
    if (samplingRate \>= 1 && samplingRate \<= 4096\) {  
      check4.points \= 10;  
      check4.status \= 'PASS';  
      check4.description \= 'Sampling rate (1:' \+ samplingRate \+ ') calibrated for hardware forwarding and collector capacity.';  
    } else {  
      check4.points \= 2;  
      check4.status \= 'FAIL';  
      check4.description \= 'Uncalibrated or unconstrained sampling rate. Risks collector packet drops or severe volumetric distortion.';  
    }  
    score \+= check4.points;  
    findings.push(check4);

    // Check 5: Security Field Coverage (TCP Flags, Proto, Ports)  
    var fields \= config.selectedFields || \[\];  
    var hasTcpFlags \= fields.indexOf('tcpControlBits') \!== \-1;  
    var hasProto \= fields.indexOf('protocolIdentifier') \!== \-1;  
    var hasPorts \= fields.indexOf('sourceTransportPort') \!== \-1 && fields.indexOf('destinationTransportPort') \!== \-1;  
    var check5 \= {  
      id: 'SECURITY\_FIELDS',  
      name: 'Essential Security Field Coverage',  
      weight: 10,  
      points: 0,  
      status: 'FAIL',  
      description: ''  
    };  
    if (hasTcpFlags && hasProto && hasPorts) {  
      check5.points \= 10;  
      check5.status \= 'PASS';  
      check5.description \= 'Full L4 security telemetry captured (TCP Flags, Protocol, L4 Ports) for SYN-flood & scan detection.';  
    } else {  
      check5.points \= 0;  
      check5.status \= 'FAIL';  
      check5.description \= 'CRITICAL: Missing essential security fields (TCP Flags: ' \+ hasTcpFlags \+ ', Ports: ' \+ hasPorts \+ ').';  
    }  
    score \+= check5.points;  
    findings.push(check5);

    // Check 6: BGP Autonomous System Attribution  
    var hasBgpAs \= fields.indexOf('bgpSourceAsNumber') \!== \-1 && fields.indexOf('bgpDestinationAsNumber') \!== \-1;  
    var check6 \= {  
      id: 'BGP\_AS\_ATTRIBUTION',  
      name: 'BGP Autonomous System Attribution',  
      weight: 10,  
      points: 0,  
      status: 'FAIL',  
      description: ''  
    };  
    if (hasBgpAs) {  
      check6.points \= 10;  
      check6.status \= 'PASS';  
      check6.description \= 'BGP Source/Destination AS numbers collected for peering traffic attribution and transit DDoS tracking.';  
    } else {  
      check6.points \= 4;  
      check6.status \= 'WARN';  
      check6.description \= 'BGP AS fields omitted. Flow records cannot identify originating/destination autonomous systems.';  
    }  
    score \+= check6.points;  
    findings.push(check6);

    // Check 7: Switch Hardware Flow Table Overload Protection  
    var tcamProtect \= \!\!config.enableTcamRateLimit;  
    var check7 \= {  
      id: 'TCAM\_PROTECTION',  
      name: 'Hardware TCAM Flow Table Overload Policer',  
      weight: 10,  
      points: 0,  
      status: 'FAIL',  
      description: ''  
    };  
    if (tcamProtect) {  
      check7.points \= 10;  
      check7.status \= 'PASS';  
      check7.description \= 'Hardware TCAM flow table rate-limiting active: Prevents switch control-plane collapse during spoofed-IP floods.';  
    } else {  
      check7.points \= 0;  
      check7.status \= 'FAIL';  
      check7.description \= 'CRITICAL DEFECT: No TCAM table protection. Random-IP SYN floods can exhaust switch forwarding memory.';  
    }  
    score \+= check7.points;  
    findings.push(check7);

    // Check 8: Transport Protocol & Collector Redundancy  
    var collectors \= config.collectors || \[\];  
    var check8 \= {  
      id: 'COLLECTOR\_REDUNDANCY',  
      name: 'Collector Resiliency & Dual Export',  
      weight: 10,  
      points: 0,  
      status: 'FAIL',  
      description: ''  
    };  
    if (collectors.length \>= 2\) {  
      check8.points \= 10;  
      check8.status \= 'PASS';  
      check8.description \= 'Dual redundant collectors configured (' \+ collectors.length \+ ' targets) for zero single point of telemetry failure.';  
    } else if (collectors.length \=== 1\) {  
      check8.points \= 6;  
      check8.status \= 'WARN';  
      check8.description \= 'Single collector configured (' \+ collectors\[0\] \+ '). Telemetry blind spot if collector node reboots.';  
    } else {  
      check8.points \= 0;  
      check8.status \= 'FAIL';  
      check8.description \= 'No telemetry collectors specified.';  
    }  
    score \+= check8.points;  
    findings.push(check8);

    // Check 9: Directional Flow Monitoring (Ingress \+ Egress)  
    var direction \= config.monitorDirection || 'both';  
    var check9 \= {  
      id: 'DIRECTIONAL\_MONITORING',  
      name: 'Directional Flow Monitoring (In/Out)',  
      weight: 10,  
      points: 0,  
      status: 'FAIL',  
      description: ''  
    };  
    if (direction \=== 'both') {  
      check9.points \= 10;  
      check9.status \= 'PASS';  
      check9.description \= 'Both ingress and egress monitoring active for asymmetric routing and transit WAN inspection.';  
    } else {  
      check9.points \= 5;  
      check9.status \= 'WARN';  
      check9.description \= 'Unidirectional monitoring (' \+ direction \+ ') leaves return traffic and egress exfiltration unmonitored.';  
    }  
    score \+= check9.points;  
    findings.push(check9);

    // Check 10: DDoS Volumetric Detection & Metric Thresholds  
    var ddosAlerts \= \!\!config.enableDdosThresholds;  
    var check10 \= {  
      id: 'DDOS\_THRESHOLDS',  
      name: 'DDoS Microburst & Volumetric Alerting',  
      weight: 10,  
      points: 0,  
      status: 'FAIL',  
      description: ''  
    };  
    if (ddosAlerts) {  
      check10.points \= 10;  
      check10.status \= 'PASS';  
      check10.description \= 'Configured with PPS and BPS microburst threshold triggers for instant SIEM / SOAR automated blackholing.';  
    } else {  
      check10.points \= 3;  
      check10.status \= 'WARN';  
      check10.description \= 'No automated volumetric thresholds configured: Dependent on manual dashboard polling.';  
    }  
    score \+= check10.points;  
    findings.push(check10);

    // Calculate Grade  
    var grade \= 'F';  
    if (score \>= 90\) grade \= 'A+';  
    else if (score \>= 80\) grade \= 'A';  
    else if (score \>= 70\) grade \= 'B';  
    else if (score \>= 60\) grade \= 'C';  
    else if (score \>= 50\) grade \= 'D';  
    else grade \= 'F';

    return {  
      score: score,  
      grade: grade,  
      passedChecks: findings.filter(function(f) { return f.status \=== 'PASS'; }).length,  
      warningChecks: findings.filter(function(f) { return f.status \=== 'WARN'; }).length,  
      failedChecks: findings.filter(function(f) { return f.status \=== 'FAIL'; }).length,  
      findings: findings  
    };  
  }

  return {  
    auditFlowConfiguration: auditFlowConfiguration  
  };  
}));  
