/\*\*  
 \* NetFlowForge Pro \- UI Orchestration & Event Controller  
 \*/

(function () {  
  'use strict';

  var currentTab \= 'cisco-xe';  
  var presets \= {  
    'enterprise-core-cisco-fnf': {  
      version: 'ipfix',  
      observationDomainId: 1,  
      templateId: 256,  
      templateRefreshSec: 60,  
      activeTimeoutSec: 30,  
      inactiveTimeoutSec: 15,  
      samplingRate: 1,  
      linkSpeedGbps: 10,  
      tcamCapacityFlows: 131072,  
      monitorDirection: 'both',  
      enableTcamRateLimit: true,  
      enableDdosThresholds: true,  
      collectors: \['198.51.100.100:2055', '198.51.100.101:2055'\],  
      selectedFields: \[  
        'sourceIPv4Address', 'destinationIPv4Address', 'protocolIdentifier', 'ipClassOfService',  
        'sourceTransportPort', 'destinationTransportPort', 'tcpControlBits', 'packetDeltaCount',  
        'octetDeltaCount', 'ingressInterface', 'egressInterface', 'bgpSourceAsNumber', 'bgpDestinationAsNumber'  
      \]  
    },  
    'cloud-ddos-juniper-inline-jflow': {  
      version: 'ipfix',  
      observationDomainId: 100,  
      templateId: 257,  
      templateRefreshSec: 60,  
      activeTimeoutSec: 30,  
      inactiveTimeoutSec: 15,  
      samplingRate: 1000,  
      linkSpeedGbps: 100,  
      tcamCapacityFlows: 262144,  
      monitorDirection: 'both',  
      enableTcamRateLimit: true,  
      enableDdosThresholds: true,  
      collectors: \['203.0.113.50:2055', '203.0.113.51:2055'\],  
      selectedFields: \[  
        'sourceIPv4Address', 'destinationIPv4Address', 'protocolIdentifier', 'sourceTransportPort',  
        'destinationTransportPort', 'tcpControlBits', 'packetDeltaCount', 'octetDeltaCount',  
        'ingressInterface', 'egressInterface', 'bgpSourceAsNumber', 'bgpDestinationAsNumber'  
      \]  
    },  
    'vulnerable-stale-netflow-config': {  
      version: 'v9',  
      observationDomainId: 1,  
      templateId: 256,  
      templateRefreshSec: 0,  
      activeTimeoutSec: 1800,  
      inactiveTimeoutSec: 600,  
      samplingRate: 1,  
      linkSpeedGbps: 40,  
      tcamCapacityFlows: 65536,  
      monitorDirection: 'input',  
      enableTcamRateLimit: false,  
      enableDdosThresholds: false,  
      collectors: \['192.168.1.50:2055'\],  
      selectedFields: \[  
        'sourceIPv4Address', 'destinationIPv4Address', 'packetDeltaCount', 'octetDeltaCount'  
      \]  
    }  
  };

  function getFormConfig() {  
    var collRaw \= document.getElementById('collectors').value.split('\\n');  
    var collectors \= \[\];  
    for (var i \= 0; i \< collRaw.length; i++) {  
      var c \= collRaw\[i\].trim();  
      if (c) collectors.push(c);  
    }

    var fields \= \[\];  
    if (document.getElementById('fSrcIp').checked) fields.push('sourceIPv4Address');  
    if (document.getElementById('fDstIp').checked) fields.push('destinationIPv4Address');  
    if (document.getElementById('fProto').checked) fields.push('protocolIdentifier');  
    if (document.getElementById('fTos').checked) fields.push('ipClassOfService');  
    if (document.getElementById('fSrcPort').checked) fields.push('sourceTransportPort');  
    if (document.getElementById('fDstPort').checked) fields.push('destinationTransportPort');  
    if (document.getElementById('fTcpFlags').checked) fields.push('tcpControlBits');  
    if (document.getElementById('fPackets').checked) fields.push('packetDeltaCount');  
    if (document.getElementById('fOctets').checked) fields.push('octetDeltaCount');  
    if (document.getElementById('fIngressIf').checked) fields.push('ingressInterface');  
    if (document.getElementById('fEgressIf').checked) fields.push('egressInterface');  
    if (document.getElementById('fBgpAs').checked) {  
      fields.push('bgpSourceAsNumber');  
      fields.push('bgpDestinationAsNumber');  
    }

    return {  
      version: document.getElementById('flowVersion').value,  
      observationDomainId: parseInt(document.getElementById('observationDomainId').value, 10\) || 1,  
      templateId: parseInt(document.getElementById('templateId').value, 10\) || 256,  
      templateRefreshSec: parseInt(document.getElementById('templateRefreshSec').value, 10\) || 0,  
      activeTimeoutSec: parseInt(document.getElementById('activeTimeoutSec').value, 10\) || 30,  
      inactiveTimeoutSec: parseInt(document.getElementById('inactiveTimeoutSec').value, 10\) || 15,  
      samplingRate: parseInt(document.getElementById('samplingRate').value, 10\) || 1,  
      linkSpeedGbps: parseFloat(document.getElementById('linkSpeedGbps').value) || 10,  
      tcamCapacityFlows: parseInt(document.getElementById('tcamCapacityFlows').value, 10\) || 131072,  
      monitorDirection: document.getElementById('monitorDirection').value,  
      enableTcamRateLimit: document.getElementById('enableTcamRateLimit').checked,  
      enableDdosThresholds: document.getElementById('enableDdosThresholds').checked,  
      collectors: collectors,  
      selectedFields: fields  
    };  
  }

  function applyPreset(presetKey) {  
    var p \= presets\[presetKey\];  
    if (\!p) return;

    document.getElementById('flowVersion').value \= p.version;  
    document.getElementById('observationDomainId').value \= p.observationDomainId;  
    document.getElementById('templateId').value \= p.templateId;  
    document.getElementById('templateRefreshSec').value \= p.templateRefreshSec;  
    document.getElementById('activeTimeoutSec').value \= p.activeTimeoutSec;  
    document.getElementById('inactiveTimeoutSec').value \= p.inactiveTimeoutSec;  
    document.getElementById('samplingRate').value \= p.samplingRate;  
    document.getElementById('linkSpeedGbps').value \= p.linkSpeedGbps;  
    document.getElementById('tcamCapacityFlows').value \= p.tcamCapacityFlows;  
    document.getElementById('monitorDirection').value \= p.monitorDirection;  
    document.getElementById('enableTcamRateLimit').checked \= p.enableTcamRateLimit;  
    document.getElementById('enableDdosThresholds').checked \= p.enableDdosThresholds;  
    document.getElementById('collectors').value \= p.collectors.join('\\n');

    document.getElementById('fSrcIp').checked \= p.selectedFields.indexOf('sourceIPv4Address') \!== \-1;  
    document.getElementById('fDstIp').checked \= p.selectedFields.indexOf('destinationIPv4Address') \!== \-1;  
    document.getElementById('fProto').checked \= p.selectedFields.indexOf('protocolIdentifier') \!== \-1;  
    document.getElementById('fTos').checked \= p.selectedFields.indexOf('ipClassOfService') \!== \-1;  
    document.getElementById('fSrcPort').checked \= p.selectedFields.indexOf('sourceTransportPort') \!== \-1;  
    document.getElementById('fDstPort').checked \= p.selectedFields.indexOf('destinationTransportPort') \!== \-1;  
    document.getElementById('fTcpFlags').checked \= p.selectedFields.indexOf('tcpControlBits') \!== \-1;  
    document.getElementById('fPackets').checked \= p.selectedFields.indexOf('packetDeltaCount') \!== \-1;  
    document.getElementById('fOctets').checked \= p.selectedFields.indexOf('octetDeltaCount') \!== \-1;  
    document.getElementById('fIngressIf').checked \= p.selectedFields.indexOf('ingressInterface') \!== \-1;  
    document.getElementById('fEgressIf').checked \= p.selectedFields.indexOf('egressInterface') \!== \-1;  
    document.getElementById('fBgpAs').checked \= p.selectedFields.indexOf('bgpSourceAsNumber') \!== \-1;

    updateStudio();  
  }

  function updateStudio() {  
    var cfg \= getFormConfig();

    // 1\. Run Auditor  
    var audit \= window.NetFlowSecurityAuditor.auditFlowConfiguration(cfg);  
    var badge \= document.getElementById('scoreBadge');  
    badge.textContent \= audit.grade;  
    badge.className \= 'score-badge ' \+ (  
      audit.grade \=== 'A+' || audit.grade \=== 'A' ? 'grade-a' :  
      audit.grade \=== 'B' ? 'grade-b' :  
      audit.grade \=== 'C' ? 'grade-c' : 'grade-f'  
    );

    document.getElementById('scoreTitle').textContent \= 'Zero-Trust Telemetry Score: ' \+ audit.score \+ ' / 100 (' \+ audit.grade \+ ')';  
    document.getElementById('scoreSummary').textContent \=  
      audit.passedChecks \+ ' Checks Passed \&bull; ' \+ audit.warningChecks \+ ' Warnings \&bull; ' \+ audit.failedChecks \+ ' Critical Risks';

    // Render 10 Rubric Items  
    var container \= document.getElementById('rubricContainer');  
    container.innerHTML \= '';  
    for (var i \= 0; i \< audit.findings.length; i++) {  
      var item \= audit.findings\[i\];  
      var div \= document.createElement('div');  
      var statusClass \= item.status \=== 'PASS' ? 'pass' : (item.status \=== 'WARN' ? 'warn' : 'fail');  
      var badgeClass \= item.status \=== 'PASS' ? 'status-pass-badge' : (item.status \=== 'WARN' ? 'status-warn-badge' : 'status-fail-badge');  
      div.className \= 'rubric-item ' \+ statusClass;  
      div.innerHTML \= '\<div\>\<strong\>' \+ (i \+ 1\) \+ '. ' \+ item.name \+ '\</strong\> (' \+ item.points \+ '/' \+ item.weight \+ ' pts)\<br\>' \+  
        '\<span style="color:var(--text-secondary);"\>' \+ item.description \+ '\</span\>\</div\>' \+  
        '\<span class="rubric-status ' \+ badgeClass \+ '"\>' \+ item.status \+ '\</span\>';  
      container.appendChild(div);  
    }

    // 2\. Flow Sizing & TCAM Calculations  
    var flowMath \= window.NetFlowEngine.computeFlowSizing({  
      linkSpeedGbps: cfg.linkSpeedGbps,  
      samplingRate: cfg.samplingRate,  
      activeTimeoutSec: cfg.activeTimeoutSec,  
      inactiveTimeoutSec: cfg.inactiveTimeoutSec,  
      tcamCapacityFlows: cfg.tcamCapacityFlows  
    });

    var tcamStatusSpan \= document.getElementById('tcamStatusText');  
    if (flowMath.status \=== 'SAFE') {  
      tcamStatusSpan.textContent \= 'TCAM Safe (' \+ flowMath.tcamUtilizationPct \+ '%)';  
      tcamStatusSpan.style.color \= '\#34d399';  
    } else if (flowMath.status \=== 'PRESSURE') {  
      tcamStatusSpan.textContent \= 'TCAM Pressure (' \+ flowMath.tcamUtilizationPct \+ '%)';  
      tcamStatusSpan.style.color \= '\#fbbf24';  
    } else {  
      tcamStatusSpan.textContent \= 'TCAM Overflow (' \+ flowMath.tcamUtilizationPct \+ '%)';  
      tcamStatusSpan.style.color \= '\#f87171';  
    }

    var usedPct \= Math.min(100, Math.max(1, flowMath.tcamUtilizationPct));  
    document.getElementById('barTcamUsed').style.width \= usedPct \+ '%';  
    document.getElementById('barTcamFree').style.width \= (100 \- usedPct) \+ '%';

    document.getElementById('valActiveFlows').textContent \= flowMath.estimatedActiveFlows.toLocaleString();  
    document.getElementById('valTcamMax').textContent \= flowMath.tcamCapacityFlows.toLocaleString();  
    document.getElementById('valExportMbps').textContent \= flowMath.exportMbps \+ ' Mbps';

    // 3\. Binary Hex Dump Wireframe  
    var msg \= window.NetFlowEngine.buildIPFIXMessage(cfg);  
    var hex \= window.NetFlowEngine.formatHexDump(msg.bytes);  
    document.getElementById('wireframeMeta').textContent \=  
      msg.version \+ ' | Total: ' \+ msg.totalLength \+ 'B (Template: ' \+ msg.templateSetLen \+ 'B | Data: ' \+ msg.dataSetLen \+ 'B)';  
    document.getElementById('hexDumpOutput').textContent \= hex;

    // 4\. Multi-Vendor Synthesizer  
    var code \= '';  
    if (currentTab \=== 'cisco-xe') code \= window.NetFlowConfigSynthesizer.synthesizeCiscoIOSXE(cfg);  
    else if (currentTab \=== 'cisco-nxos') code \= window.NetFlowConfigSynthesizer.synthesizeCiscoNXOS(cfg);  
    else if (currentTab \=== 'juniper') code \= window.NetFlowConfigSynthesizer.synthesizeJuniperJunos(cfg);  
    else if (currentTab \=== 'arista') code \= window.NetFlowConfigSynthesizer.synthesizeAristaEOS(cfg);  
    else if (currentTab \=== 'linux') {  
      code \= window.NetFlowConfigSynthesizer.synthesizeLinuxOVS(cfg) \+ '\\n\\n' \+  
             window.NetFlowConfigSynthesizer.synthesizePrometheusExporter(cfg);  
    }

    document.getElementById('configOutput').textContent \= code;  
  }

  // Event Listeners  
  document.addEventListener('DOMContentLoaded', function () {  
    var inputs \= document.querySelectorAll('input, select, textarea');  
    for (var i \= 0; i \< inputs.length; i++) {  
      inputs\[i\].addEventListener('input', updateStudio);  
      inputs\[i\].addEventListener('change', updateStudio);  
    }

    document.getElementById('presetSelect').addEventListener('change', function (e) {  
      applyPreset(e.target.value);  
    });

    var tabBtns \= document.querySelectorAll('.tab-btn');  
    for (var j \= 0; j \< tabBtns.length; j++) {  
      tabBtns\[j\].addEventListener('click', function (e) {  
        for (var k \= 0; k \< tabBtns.length; k++) tabBtns\[k\].classList.remove('active');  
        e.target.classList.add('active');  
        currentTab \= e.target.getAttribute('data-tab');  
        updateStudio();  
      });  
    }

    document.getElementById('copyConfigBtn').addEventListener('click', function () {  
      var text \= document.getElementById('configOutput').textContent;  
      navigator.clipboard.writeText(text).then(function () {  
        var btn \= document.getElementById('copyConfigBtn');  
        btn.textContent \= 'Copied\!';  
        setTimeout(function () { btn.textContent \= 'Copy Config'; }, 2000);  
      });  
    });

    document.getElementById('exportJsonBtn').addEventListener('click', function () {  
      var cfg \= getFormConfig();  
      var jsonStr \= JSON.stringify(cfg, null, 2);  
      var blob \= new Blob(\[jsonStr\], { type: 'application/json' });  
      var url \= URL.createObjectURL(blob);  
      var a \= document.createElement('a');  
      a.href \= url;  
      a.download \= 'flow-telemetry-config.json';  
      a.click();  
      URL.revokeObjectURL(url);  
    });

    // Initial render  
    updateStudio();  
  });  
})();  
