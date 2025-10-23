import { useState } from "react";
import { motion } from "framer-motion";
import { Download, Clock, FileText, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { irPlaybooks } from "@/lib/data";

export default function IRPlaybooks() {
  const [activeFilter, setActiveFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");

  const filters = [
    { id: "all", label: "All Playbooks" },
    { id: "cloud-security", label: "Cloud Security" },
    { id: "endpoint-security", label: "Endpoint Security" },
    { id: "email-security", label: "Email Security" },
    { id: "web-security", label: "Web Security" },
  ];

  const filteredPlaybooks = irPlaybooks.filter(playbook => {
    // 1. Check if it matches the active category filter
    const categoryMatch = 
      activeFilter === "all" || 
      playbook.category.toLowerCase().replace(/\s+/g, '-') === activeFilter;

    // 2. Check if it matches the search query (case-insensitive)
    const query = searchQuery.toLowerCase();
    
    // Search within title, description, and category
    const textMatch = 
      playbook.title.toLowerCase().includes(query) ||
      playbook.description.toLowerCase().includes(query) ||
      playbook.category.toLowerCase().includes(query);

    // NEW: Search within MITRE mappings (ID and Name)
    const mitreMatch = playbook.mitreMapping?.some(tactic => 
      tactic.techniques.some(technique => 
        technique.id.toLowerCase().includes(query) ||
        technique.name.toLowerCase().includes(query)
      )
    ) || false; // Default to false if no mitreMapping exists

    const searchMatch = !query || textMatch || mitreMatch;

    // 3. The playbook must match both the category and search filters
    return categoryMatch && searchMatch;
  });

  const downloadPlaybook = (pdfUrl: string, title: string) => {
    const link = document.createElement('a');
    link.href = pdfUrl;
    link.download = `${title.toLowerCase().replace(/\s+/g, '-')}.pdf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <section id="ir-playbooks" className="py-20 bg-muted/30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <h2 className="text-3xl sm:text-4xl font-bold mb-4">Incident Response Playbooks</h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Ready-to-use incident response playbooks covering common attack scenarios. 
            Download detailed PDF guides with step-by-step procedures.
          </p>
        </motion.div>

        {/* Search Bar */}
        <div className="mb-8 flex flex-col sm:flex-row gap-4 justify-center items-center">
          <div className="relative w-full sm:w-72">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
            <Input
              type="text"
              placeholder="Search by title, MITRE ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
              data-testid="playbook-search-input"
            />
          </div>
        </div>
        
        {/* Category Filters */}
        <div className="mb-8 flex flex-wrap gap-4 justify-center">
          {filters.map((filter) => (
            <Button
              key={filter.id}
              variant={activeFilter === filter.id ? "default" : "outline"}
              onClick={() => setActiveFilter(filter.id)}
              className={`${
                activeFilter === filter.id
                  ? "bg-primary/20 text-primary border-primary/50 hover:bg-primary hover:text-primary-foreground"
                  : "bg-muted hover:bg-secondary/20 text-muted-foreground hover:text-secondary border-border"
              } transition-all duration-200`}
              data-testid={`filter-${filter.id}`}
            >
              {filter.label}
            </Button>
          ))}
        </div>

        {/* Playbooks Grid */}
        <motion.div
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8"
          layout
        >
          {filteredPlaybooks.map((playbook, index) => (
            <motion.div
              key={playbook.id}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: index * 0.1 }}
              viewport={{ once: true }}
              className="bg-card border border-border rounded-lg overflow-hidden hover:border-primary/50 transition-all duration-300 group hover:shadow-lg hover:shadow-primary/10"
              data-testid={`playbook-card-${playbook.id}`}
            >
              {/* PDF Thumbnail */}
              <div className={`aspect-[4/3] bg-gradient-to-br ${
                playbook.category === "Endpoint Security" ? "from-destructive/10 to-primary/10" :
                playbook.category === "Email Security" ? "from-secondary/10 to-accent/10" :
                playbook.category === "Web Security" ? "from-accent/10 to-destructive/10" :
                "from-primary/10 to-secondary/10"
              } flex items-center justify-center border-b border-border`}>
                <div className="text-center">
                  <FileText className="w-16 h-16 mx-auto text-muted-foreground mb-2" />
                  <div className="text-sm text-muted-foreground font-medium">
                    {playbook.title}
                  </div>
                </div>
              </div>
              
              <div className="p-6">
                <div className="flex justify-between items-start mb-3">
                  <h3 className="font-semibold text-lg group-hover:text-primary transition-colors">
                    {playbook.title}
                  </h3>
                  <span className={`text-xs px-2 py-1 rounded-full ${
                    playbook.category === "Endpoint Security" ? "bg-destructive/20 text-destructive" :
                    playbook.category === "Email Security" ? "bg-accent/20 text-accent" :
                    playbook.category === "Web Security" ? "bg-destructive/20 text-destructive" :
                    "bg-secondary/20 text-secondary"
                  }`}>
                    {playbook.category}
                  </span>
                </div>
                
                <p className="text-muted-foreground text-sm mb-4 line-clamp-3">
                  {playbook.description}
                </p>
                
                <div className="flex justify-between items-center">
                  <div className="text-xs text-muted-foreground flex items-center space-x-2">
                    <Clock className="w-4 h-4" />
                    <span>{playbook.readingTime}</span>
                  </div>
                  <Button
                    onClick={() => downloadPlaybook(playbook.pdfUrl, playbook.title)}
                    className="bg-primary hover:bg-primary/80 text-primary-foreground px-4 py-2 text-sm font-semibold transition-all duration-300 flex items-center space-x-2"
                    data-testid={`download-${playbook.id}`}
                  >
                    <Download className="w-4 h-4" />
                    <span>Download</span>
                  </Button>
                </div>
              </div>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}