import { useState } from "react";
import { motion } from "framer-motion";
import { Download, Clock, Search, Filter, Cpu } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { investigationPlaybooks } from "@/lib/data";

export default function InvestigationPlaybooks() {
  const [searchQuery, setSearchQuery] = useState("");
  const [activeFilter, setActiveFilter] = useState("all");

  const filters = [
    { id: "all", label: "All Playbooks" },
    { id: "forensics", label: "Forensics" },
    { id: "network", label: "Network" },
    { id: "memory", label: "Memory" },
  ];

  const downloadPlaybook = (pdfUrl: string, title: string) => {
    const link = document.createElement('a');
    link.href = pdfUrl;
    link.download = `${title.toLowerCase().replace(/\s+/g, '-')}.pdf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getIcon = (category: string) => {
    switch (category) {
      case "Forensics":
        return <Search className="w-16 h-16 mx-auto text-muted-foreground mb-2" />;
      case "Network":
        return <Filter className="w-16 h-16 mx-auto text-muted-foreground mb-2" />;
      case "Memory":
        return <Cpu className="w-16 h-16 mx-auto text-muted-foreground mb-2" />;
      default:
        return <Search className="w-16 h-16 mx-auto text-muted-foreground mb-2" />;
    }
  };

  const filteredPlaybooks = investigationPlaybooks.filter(playbook => {
    const categoryMatch =
      activeFilter === "all" ||
      playbook.category.toLowerCase() === activeFilter;

    const query = searchQuery.toLowerCase();
    const searchMatch =
      !query ||
      playbook.title.toLowerCase().includes(query) ||
      playbook.description.toLowerCase().includes(query) ||
      playbook.category.toLowerCase().includes(query);

    return categoryMatch && searchMatch;
  });

  return (
    <section id="investigation-playbooks" className="py-20 bg-background">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <h2 className="text-3xl sm:text-4xl font-bold mb-4">Investigation Playbooks</h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Detailed investigation procedures and methodologies. 
            Forensic analysis guides and evidence collection protocols.
          </p>
        </motion.div>

        {/* Search Bar */}
        <div className="mb-8 flex justify-center">
          <div className="relative w-full sm:w-72">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
            <Input
              type="text"
              placeholder="Search investigations..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
              data-testid="investigation-search-input"
            />
          </div>
        </div>

        {/* Category Filters */}
        <div className="mb-12 flex flex-wrap gap-4 justify-center">
          {filters.map((filter) => (
            <Button
              key={filter.id}
              variant={activeFilter === filter.id ? "default" : "outline"}
              onClick={() => setActiveFilter(filter.id)}
              className={`${
                activeFilter === filter.id
                  ? "bg-secondary/20 text-secondary border-secondary/50 hover:bg-secondary hover:text-secondary-foreground"
                  : "bg-muted hover:bg-primary/20 text-muted-foreground hover:text-primary border-border"
              } transition-all duration-200`}
              data-testid={`filter-${filter.id}`}
            >
              {filter.label}
            </Button>
          ))}
        </div>

        {/* Investigation Playbooks Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {filteredPlaybooks.map((playbook, index) => (
            <motion.div
              key={playbook.id}
              // ... (rest of the card component is unchanged)
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: index * 0.1 }}
              viewport={{ once: true }}
              className="bg-card border border-border rounded-lg overflow-hidden hover:border-secondary/50 transition-all duration-300 group hover:shadow-lg hover:shadow-secondary/10"
              data-testid={`investigation-card-${playbook.id}`}
            >
              <div className={`aspect-[4/3] bg-gradient-to-br ${
                playbook.category === "Forensics" ? "from-secondary/10 to-primary/10" :
                playbook.category === "Network" ? "from-accent/10 to-secondary/10" :
                "from-primary/10 to-accent/10"
              } flex items-center justify-center border-b border-border`}>
                <div className="text-center">
                  {getIcon(playbook.category)}
                  <div className="text-sm text-muted-foreground font-medium">
                    {playbook.category}
                  </div>
                </div>
              </div>
              
              <div className="p-6">
                <div className="flex justify-between items-start mb-3">
                  <h3 className="font-semibold text-lg group-hover:text-secondary transition-colors">
                    {playbook.title}
                  </h3>
                  <span className={`text-xs px-2 py-1 rounded-full ${
                    playbook.category === "Forensics" ? "bg-secondary/20 text-secondary" :
                    playbook.category === "Network" ? "bg-accent/20 text-accent" :
                    "bg-primary/20 text-primary"
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
                    className="bg-secondary hover:bg-secondary/80 text-secondary-foreground px-4 py-2 text-sm font-semibold transition-all duration-300 flex items-center space-x-2"
                    data-testid={`download-investigation-${playbook.id}`}
                  >
                    <Download className="w-4 h-4" />
                    <span>Download</span>
                  </Button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}