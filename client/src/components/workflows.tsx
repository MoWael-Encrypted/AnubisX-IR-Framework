import { useState } from "react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { workflows } from "@/lib/data";

export default function Workflows() {
  const [activeFilter, setActiveFilter] = useState("all");

  const filters = [
    { id: "all", label: "All Tools" },
    { id: "siem", label: "SIEM" },
    { id: "edr", label: "EDR" },
    { id: "firewall", label: "Firewall" },
    { id: "soar", label: "SOAR" },
  ];

  const filteredWorkflows = activeFilter === "all" 
    ? workflows 
    : workflows.filter(workflow => workflow.tool.toLowerCase() === activeFilter);

  return (
    <section id="workflows" className="py-20 bg-muted/30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <h2 className="text-3xl sm:text-4xl font-bold mb-4">Automated Response Workflows</h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Pre-built automation workflows for common incident response scenarios. 
            Visual guides with screenshots and implementation steps.
          </p>
        </motion.div>

        {/* Tool Filters */}
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

        {/* Workflows Grid */}
        <div className="space-y-12">
          {filteredWorkflows.map((workflow, index) => (
            <motion.div
              key={workflow.id}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: index * 0.2 }}
              viewport={{ once: true }}
              className="bg-card border border-border rounded-lg overflow-hidden hover:border-accent/50 transition-all duration-300 hover:shadow-lg hover:shadow-accent/10"
              data-testid={`workflow-card-${workflow.id}`}
            >
              <div className="p-8">
                <div className="flex justify-between items-start mb-6">
                  <div>
                    <h3 className="text-2xl font-semibold mb-2">{workflow.title}</h3>
                    <p className="text-muted-foreground">{workflow.description}</p>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                    workflow.tool === "SOAR" ? "bg-accent/20 text-accent" :
                    workflow.tool === "SIEM" ? "bg-secondary/20 text-secondary" :
                    workflow.tool === "EDR" ? "bg-primary/20 text-primary" :
                    "bg-destructive/20 text-destructive"
                  }`}>
                    {workflow.tool}
                  </span>
                </div>

                {/* Screenshot Placeholder */}
                <div className={`bg-gradient-to-br ${
                  workflow.tool === "SOAR" ? "from-accent/10 to-primary/10" :
                  workflow.tool === "SIEM" ? "from-secondary/10 to-accent/10" :
                  "from-primary/10 to-secondary/10"
                } rounded-lg p-8 mb-6 border border-border/50`}>
                  <div className="flex items-center justify-center h-64">
                    <div className="text-center">
                      {/* Mockup workflow dashboard */}
                      <div className="bg-background/50 rounded-lg p-4 mb-4 max-w-md mx-auto">
                        <div className="flex items-center justify-between mb-2">
                          <div className={`w-3 h-3 rounded-full ${
                            workflow.tool === "SOAR" ? "bg-accent" :
                            workflow.tool === "SIEM" ? "bg-secondary" :
                            "bg-primary"
                          }`}></div>
                          <div className="text-xs text-muted-foreground">{workflow.tool} Workflow</div>
                          <div className="w-3 h-3 bg-primary rounded-full"></div>
                        </div>
                        <div className="space-y-2">
                          <div className={`h-2 rounded-full w-full ${
                            workflow.tool === "SOAR" ? "bg-accent/50" :
                            workflow.tool === "SIEM" ? "bg-secondary/50" :
                            "bg-primary/50"
                          }`}></div>
                          <div className="h-2 bg-primary/50 rounded-full w-3/4"></div>
                          <div className="h-2 bg-secondary/50 rounded-full w-1/2"></div>
                        </div>
                      </div>
                      <div className="text-muted-foreground text-sm">Workflow Dashboard Screenshot</div>
                    </div>
                  </div>
                </div>

                {/* Step-by-step explanation */}
                <div className="space-y-4">
                  <h4 className={`text-lg font-semibold ${
                    workflow.tool === "SOAR" ? "text-accent" :
                    workflow.tool === "SIEM" ? "text-secondary" :
                    "text-primary"
                  }`}>
                    Implementation Steps:
                  </h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {workflow.steps.map((step, stepIndex) => (
                      <div
                        key={stepIndex}
                        className="bg-muted/50 rounded-lg p-4 border border-border/50"
                        data-testid={`workflow-step-${workflow.id}-${stepIndex}`}
                      >
                        <div className="flex items-center mb-2">
                          <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold mr-3 ${
                            workflow.tool === "SOAR" ? "bg-accent text-accent-foreground" :
                            workflow.tool === "SIEM" ? "bg-secondary text-secondary-foreground" :
                            "bg-primary text-primary-foreground"
                          }`}>
                            {stepIndex + 1}
                          </div>
                          <h5 className="font-semibold">{step.title}</h5>
                        </div>
                        <p className="text-sm text-muted-foreground">{step.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
