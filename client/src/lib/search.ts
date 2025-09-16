import { useState, useCallback } from "react";
import Fuse from "fuse.js";
import { detectionRules, irPlaybooks, investigationPlaybooks, workflows, teamMembers } from "./data";

export interface SearchResult {
  id: string;
  title: string;
  description: string;
  type: string;
  section: string;
}

const searchData: SearchResult[] = [
  ...detectionRules.map(rule => ({
    id: rule.id,
    title: rule.title,
    description: rule.description,
    type: "Detection Rule",
    section: "detection-rules"
  })),
  ...irPlaybooks.map(playbook => ({
    id: playbook.id,
    title: playbook.title,
    description: playbook.description,
    type: "IR Playbook",
    section: "ir-playbooks"
  })),
  ...investigationPlaybooks.map(playbook => ({
    id: playbook.id,
    title: playbook.title,
    description: playbook.description,
    type: "Investigation Playbook",
    section: "investigation-playbooks"
  })),
  ...workflows.map(workflow => ({
    id: workflow.id,
    title: workflow.title,
    description: workflow.description,
    type: "Workflow",
    section: "workflows"
  })),
  ...teamMembers.map(member => ({
    id: member.id,
    title: member.name,
    description: `${member.role} - ${member.bio}`,
    type: "Team Member",
    section: "about"
  }))
];

const fuse = new Fuse(searchData, {
  keys: ["title", "description", "type"],
  threshold: 0.3,
  includeScore: true
});

export function useSearch() {
  const [results, setResults] = useState<SearchResult[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const search = useCallback((query: string) => {
    if (!query.trim()) {
      setResults([]);
      return;
    }

    setIsLoading(true);
    
    // Simulate network delay for better UX
    setTimeout(() => {
      const searchResults = fuse.search(query);
      setResults(searchResults.map(result => result.item));
      setIsLoading(false);
    }, 200);
  }, []);

  return { search, results, isLoading };
}
