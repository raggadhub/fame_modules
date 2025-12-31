import hashlib

from fame.core.module import ProcessingModule, ModuleInitializationError

try:
    from vt import Client, url_id
    HAVE_VIRUSTOTAL = True
except ImportError:
    HAVE_VIRUSTOTAL = False


class VirusTotalPublic3(ProcessingModule):
    name = "virustotal_public_v3"
    description = "Get Scan Report from VirusTotal REST API v3 (Public API)"
    config = [
        {
            "name": "api_key",
            "type": "string",
            "description": "API Key needed to use the VirusTotal Public APIv3",
        }
    ]

    def initialize(self):
        if not HAVE_VIRUSTOTAL:
            raise ModuleInitializationError(self, "Missing dependency: vt-py")
        return True

    def each_with_type(self, target, target_type):
        self.results = {}
        vtc = Client(self.api_key)
        if target_type == "url":
            urlid = url_id(target)
            response = vtc.get_object("/urls/{}" + urlid)
            self.results["threat_severity"] = response.threat_severity["level_description"]
            try:
                response = vtc.get_object("/urls/{}" + urlid)
                self.results["threat_severity"] = response.threat_severity["level_description"]
            except Exception:
                self.log("debug", "no report found")
        else:
            with open(target, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            try:
                response = vtc.get_object(str("/files/", sha256))
                self.results["threat_severity"] = response.threat_severity["level_description"]
            except Exception:
                self.log("debug", "no report found")
        return True
