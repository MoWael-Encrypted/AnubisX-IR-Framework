import { Github, Twitter, Linkedin } from "lucide-react";

export default function Footer() {
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      const headerOffset = 80;
      const elementPosition = element.getBoundingClientRect().top;
      const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

      window.scrollTo({
        top: offsetPosition,
        behavior: "smooth"
      });
    }
  };

  return (
    <footer className="bg-muted/30 border-t border-border">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="col-span-1 md:col-span-2">
            <div className="flex items-center space-x-2 mb-4">
              <div className="w-10 h-10 bg-gradient-to-br from-primary to-secondary rounded-lg flex items-center justify-center">
                <span className="text-primary-foreground font-bold text-xl">A</span>
              </div>
              <span className="text-xl font-bold bg-gradient-to-r from-primary to-secondary bg-clip-text text-transparent">
                AnubisX
              </span>
            </div>
            <p className="text-muted-foreground mb-6 max-w-md">
              Open-source incident response framework providing detection rules, 
              playbooks, and automation workflows for security teams worldwide.
            </p>
            <div className="flex space-x-4">
              <a 
                href="#" 
                className="text-muted-foreground hover:text-primary transition-colors"
                data-testid="footer-github"
              >
                <Github className="w-6 h-6" />
              </a>
              <a 
                href="#" 
                className="text-muted-foreground hover:text-primary transition-colors"
                data-testid="footer-twitter"
              >
                <Twitter className="w-6 h-6" />
              </a>
              <a 
                href="#" 
                className="text-muted-foreground hover:text-primary transition-colors"
                data-testid="footer-linkedin"
              >
                <Linkedin className="w-6 h-6" />
              </a>
            </div>
          </div>
          
          <div>
            <h3 className="text-sm font-semibold text-foreground uppercase tracking-wider mb-4">
              Resources
            </h3>
            <ul className="space-y-3">
              <li>
                <button
                  onClick={() => scrollToSection("detection-rules")}
                  className="text-muted-foreground hover:text-primary text-sm transition-colors"
                  data-testid="footer-detection-rules"
                >
                  Detection Rules
                </button>
              </li>
              <li>
                <button
                  onClick={() => scrollToSection("ir-playbooks")}
                  className="text-muted-foreground hover:text-primary text-sm transition-colors"
                  data-testid="footer-ir-playbooks"
                >
                  IR Playbooks
                </button>
              </li>
              <li>
                <button
                  onClick={() => scrollToSection("investigation-playbooks")}
                  className="text-muted-foreground hover:text-primary text-sm transition-colors"
                  data-testid="footer-investigation"
                >
                  Investigation
                </button>
              </li>
              <li>
                <button
                  onClick={() => scrollToSection("workflows")}
                  className="text-muted-foreground hover:text-primary text-sm transition-colors"
                  data-testid="footer-workflows"
                >
                  Workflows
                </button>
              </li>
            </ul>
          </div>
          
          <div>
            <h3 className="text-sm font-semibold text-foreground uppercase tracking-wider mb-4">
              Community
            </h3>
            <ul className="space-y-3">
              <li>
                <a href="#" className="text-muted-foreground hover:text-primary text-sm transition-colors" data-testid="footer-discord">
                  Discord
                </a>
              </li>
              <li>
                <a href="#" className="text-muted-foreground hover:text-primary text-sm transition-colors" data-testid="footer-github-link">
                  GitHub
                </a>
              </li>
              <li>
                <a href="#" className="text-muted-foreground hover:text-primary text-sm transition-colors" data-testid="footer-contributing">
                  Contributing
                </a>
              </li>
              <li>
                <button
                  onClick={() => scrollToSection("about")}
                  className="text-muted-foreground hover:text-primary text-sm transition-colors"
                  data-testid="footer-about"
                >
                  About Us
                </button>
              </li>
            </ul>
          </div>
        </div>
        
        <div className="border-t border-border mt-8 pt-8 text-center">
          <p className="text-muted-foreground text-sm">
            © 2024 AnubisX. All rights reserved. Open source under MIT License.
          </p>
        </div>
      </div>
    </footer>
  );
}
