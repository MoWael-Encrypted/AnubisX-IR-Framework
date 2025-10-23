import { useState } from "react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Search } from "lucide-react";
import { detectionRules } from "@/lib/data";

export default function DetectionRules() {
  const [activeFilter, setActiveFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [visibleRules, setVisibleRules] = useState(9);

  const filters = [
    { id: "all", label: "All Rules" },
    { id: "sigma", label: "Sigma" },
    { id: "yara", label: "YARA" },
    { id: "snort", label: "Snort" },
    { id: "suricata", label: "Suricata" },
  ];

  const filteredRules = detectionRules.filter(rule => {
    // 1. Check if it matches the active language filter
    const languageMatch =
      activeFilter === "all" ||
      rule.language.toLowerCase() === activeFilter;

    // 2. Check if it matches the search query (case-insensitive)
    const query = searchQuery.toLowerCase();
    const searchMatch =
      !query ||
      rule.title.toLowerCase().includes(query) ||
      rule.description.toLowerCase().includes(query) ||
      rule.mitreTechnique.toLowerCase().includes(query) ||
      rule.category.toLowerCase().includes(query);

    // 3. The rule must match both
    return languageMatch && searchMatch;
  });

  const displayedRules = filteredRules.slice(0, visibleRules);

  const loadMore = () => {
    setVisibleRules(prev => prev + 9);
  };

  return (
    <section id="detection-rules" className="py-20 bg-background">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <h2 className="text-3xl sm:text-4xl font-bold mb-4">Detection Rules</h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Comprehensive collection of detection rules mapped to MITRE ATT&CK framework, 
            organized by detection language and threat tactics.
          </p>
        </motion.div>

        {/* Search Bar */}
        <div className="mb-8 flex justify-center">
          <div className="relative w-full sm:w-72">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
            <Input
              type="text"
              placeholder="Search rules..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setVisibleRules(9); // Reset pagination on search
              }}
              className="pl-10"
              data-testid="rule-search-input"
            />
          </div>
        </div>

        {/* Filters */}
        <div className="mb-8 flex flex-wrap gap-4 justify-center">
          {filters.map((filter) => (
            <Button
              key={filter.id}
              variant={activeFilter === filter.id ? "default" : "outline"}
              onClick={() => {
                setActiveFilter(filter.id);
                setVisibleRules(9);
              }}
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

        {/* Rules Grid */}
        <motion.div
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
          layout
        >
          {displayedRules.map((rule, index) => (
            <motion.div
              key={rule.id}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: index * 0.1 }}
              viewport={{ once: true }}
              className="bg-card border border-border rounded-lg p-6 hover:border-primary/50 transition-all duration-300 group hover:shadow-lg hover:shadow-primary/10"
              data-testid={`rule-card-${rule.id}`}
            >
              <div className="flex justify-between items-start mb-3">
                <h3 className="font-semibold text-lg group-hover:text-primary transition-colors">
                  {rule.title}
                </h3>
                <span className={`text-xs px-2 py-1 rounded-full ${
                  rule.language === "Sigma" ? "bg-primary/20 text-primary" :
                  rule.language === "YARA" ? "bg-secondary/20 text-secondary" :
                  rule.language === "Snort" ? "bg-accent/20 text-accent" :
                  "bg-destructive/20 text-destructive"
                }`}>
                  {rule.language}
                </span>
              </div>
              
              <div className="flex flex-wrap gap-1 mb-3">
                <span className="bg-secondary/20 text-secondary text-xs px-2 py-1 rounded-full">
                  {rule.mitreId}
                </span>
                <span className="bg-accent/20 text-accent text-xs px-2 py-1 rounded-full">
                  {rule.mitreTechnique}
                </span>
              </div>
              
              <div className="bg-muted rounded-md p-3 mb-4 text-sm font-mono text-muted-foreground overflow-x-auto">
                <code>{rule.snippet}</code>
              </div>
              
              <div className="flex justify-between items-center">
                <span className="text-xs text-muted-foreground">{rule.category}</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-primary hover:text-primary/80 text-sm font-medium"
                  data-testid={`view-rule-${rule.id}`}
                >
                  View Full Rule →
                </Button>
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* Load More Button */}
        {visibleRules < filteredRules.length && (
          <div className="text-center mt-12">
            <Button
              onClick={loadMore}
              variant="outline"
              className="bg-primary/10 hover:bg-primary text-primary hover:text-primary-foreground border-primary/50 px-8 py-3 font-semibold"
              data-testid="load-more-rules"
            >
              Load More Rules
            </Button>
          </div>
        )}
      </div>
    </section>
  );
} 