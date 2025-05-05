import dspy
import trafilatura


class BasicHtmlToTextParser(dspy.Module):
    def __init__(self, include_images: bool = False):
        self.include_images = include_images
    
    def forward(self, threat_report_html: str) -> str:
        text = trafilatura.extract(threat_report_html, include_images=self.include_images)   
        return text