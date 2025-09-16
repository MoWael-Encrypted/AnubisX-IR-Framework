import { useState, useEffect } from "react";
import { X, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useSearch } from "@/lib/search";

interface SearchOverlayProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function SearchOverlay({ isOpen, onClose }: SearchOverlayProps) {
  const [query, setQuery] = useState("");
  const { search, results, isLoading } = useSearch();

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "unset";
      setQuery("");
    }

    return () => {
      document.body.style.overflow = "unset";
    };
  }, [isOpen]);

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener("keydown", handleEscape);
    }

    return () => {
      document.removeEventListener("keydown", handleEscape);
    };
  }, [isOpen, onClose]);

  useEffect(() => {
    if (query.trim()) {
      search(query);
    }
  }, [query, search]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 search-overlay z-50 flex items-center justify-center p-4">
      <div className="bg-card rounded-xl border border-border max-w-2xl w-full p-6 animate-slide-up">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold" data-testid="search-title">Search AnubisX</h3>
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            data-testid="search-close-button"
          >
            <X className="w-6 h-6" />
          </Button>
        </div>
        
        <div className="relative mb-4">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            type="text"
            placeholder="Search rules, playbooks, workflows..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full pl-10 bg-input border border-border rounded-lg py-3 text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
            autoFocus
            data-testid="search-input"
          />
        </div>

        <div className="space-y-2 max-h-96 overflow-y-auto" data-testid="search-results">
          {!query.trim() && (
            <div className="text-sm text-muted-foreground text-center py-8">
              Start typing to search across all content...
            </div>
          )}
          
          {query.trim() && isLoading && (
            <div className="text-sm text-muted-foreground text-center py-8">
              Searching...
            </div>
          )}
          
          {query.trim() && !isLoading && results.length === 0 && (
            <div className="text-sm text-muted-foreground text-center py-8">
              No results found for "{query}"
            </div>
          )}
          
          {results.map((result) => (
            <div
              key={result.id}
              className="p-3 rounded-lg border border-border hover:border-primary/50 cursor-pointer transition-colors"
              onClick={() => {
                const element = document.getElementById(result.section);
                if (element) {
                  onClose();
                  setTimeout(() => {
                    element.scrollIntoView({ behavior: "smooth" });
                  }, 100);
                }
              }}
              data-testid={`search-result-${result.id}`}
            >
              <div className="flex justify-between items-start mb-1">
                <h4 className="font-medium text-sm">{result.title}</h4>
                <span className="text-xs text-muted-foreground bg-muted px-2 py-1 rounded">
                  {result.type}
                </span>
              </div>
              <p className="text-xs text-muted-foreground line-clamp-2">
                {result.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
