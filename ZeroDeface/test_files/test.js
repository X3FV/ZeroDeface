// Safe JavaScript upload test
alert("SECURITY_TEST: JS file loaded successfully");
document.write(
    '<div style="position:fixed;top:0;left:0;width:100%;' +
    'background:red;color:white;padding:10px;text-align:center;">' +
    'DEFACED_BY_ZEROSCOPE_TEST (Simulated)<br>' +
    'TEST_ID: ZS-JS-' + Date.now().toString(36) +
    '</div>'
);

// Non-malicious fingerprinting
console.log({
    vulnerability: "File upload",
    status: "Confirmed",
    testId: "ZS-JS-" + Math.random().toString(36).slice(2),
    warning: "This is a security test file"
});