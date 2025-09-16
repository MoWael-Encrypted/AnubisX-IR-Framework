import Navigation from "@/components/navigation";
import SearchOverlay from "@/components/search-overlay";
import HeroSection from "@/components/hero-section";
import DetectionRules from "@/components/detection-rules";
import IRPlaybooks from "@/components/ir-playbooks";
import InvestigationPlaybooks from "@/components/investigation-playbooks";
import Workflows from "@/components/workflows";
import AboutUs from "@/components/about-us";
import Footer from "@/components/footer";
import { useState } from "react";

export default function Home() {
  const [isSearchOpen, setIsSearchOpen] = useState(false);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navigation onSearchClick={() => setIsSearchOpen(true)} />
      <SearchOverlay isOpen={isSearchOpen} onClose={() => setIsSearchOpen(false)} />
      
      <HeroSection />
      <DetectionRules />
      <IRPlaybooks />
      <InvestigationPlaybooks />
      <Workflows />
      <AboutUs />
      <Footer />
    </div>
  );
}
