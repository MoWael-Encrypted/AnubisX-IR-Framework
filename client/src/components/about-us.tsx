import { motion } from "framer-motion";
import { Briefcase,Linkedin } from "lucide-react";
import { Button } from "@/components/ui/button";
import { teamMembers } from "@/lib/data";

export default function AboutUs() {
  return (
    <section id="about" className="py-20 bg-background">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <h2 className="text-3xl sm:text-4xl font-bold mb-4">Meet the AnubisX Team</h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Security professionals and researchers dedicated to advancing incident response capabilities 
            through open-source tools and knowledge sharing.
          </p>
        </motion.div>

        {/* Team Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 mb-16">
          {teamMembers.map((member, index) => (
            <motion.div
              key={member.id}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: index * 0.1 }}
              viewport={{ once: true }}
              className="group"
              data-testid={`team-member-${member.id}`}
            >
              <div className={`relative bg-card border border-border rounded-lg overflow-hidden transition-all duration-500 hover:border-${member.color}/50 hover:shadow-lg hover:shadow-${member.color}/10 transform-gpu hover:scale-105`}>
                {/* Profile image */}
                <div className="relative overflow-hidden">
                  <img 
                    src={member.image}
                    alt={`${member.name} professional headshot`}
                    className="w-full h-64 object-cover transition-transform duration-500 group-hover:scale-110"
                  />
                  
                  {/* Overlay that appears on hover */}
                  <div className="absolute inset-0 bg-gradient-to-t from-background via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                </div>
                
                {/* Content */}
                <div className="p-6 relative">
                  <h3 className={`text-xl font-semibold mb-1 group-hover:text-${member.color} transition-colors`}>
                    {member.name}
                  </h3>
                  <p className={`text-${member.color} text-sm font-medium mb-3`}>
                    {member.role}
                  </p>
                  <p className="text-muted-foreground text-sm mb-4 line-clamp-3">
                    {member.bio}
                  </p>
                  
                  {/* Social Links */}
                  <div className="flex space-x-3 opacity-0 group-hover:opacity-100 transition-opacity duration-500">
                    <a 
                      href={member.linkedin}
                      className={`text-muted-foreground hover:text-${member.color} transition-colors`}
                      data-testid={`linkedin-${member.id}`}
                    >
                      <Linkedin className="w-5 h-5" />
                    </a>
                    <a 
                      href={member.portfolio}
                      className={`text-muted-foreground hover:text-${member.color} transition-colors`}
                      data-testid={`portfolio-${member.id}`}
                    >
                      <Briefcase className="w-5 h-5" />
                    </a>
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Call to Action */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center"
        >
          <div className="bg-gradient-to-r from-primary/10 to-secondary/10 rounded-lg p-8 border border-primary/20">
            <h3 className="text-2xl font-semibold mb-4">Join the Community</h3>
            <p className="text-muted-foreground mb-6 max-w-2xl mx-auto">
              Connect with security professionals, contribute to open-source projects, 
              and help advance incident response capabilities.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Button
                className="bg-primary hover:bg-primary/80 text-primary-foreground px-6 py-3 font-semibold"
                data-testid="join-discord-button"
              >
                Join Discord
              </Button>
              <Button
                variant="outline"
                className="border-border hover:border-secondary text-foreground hover:text-secondary px-6 py-3 font-semibold"
                data-testid="github-contribute-button"
              >
                Contribute on GitHub
              </Button>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
