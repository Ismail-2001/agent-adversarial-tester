"""Cost estimation utilities for LLM-based security scanning."""

from __future__ import annotations

from typing import Dict, List, Optional
from ..models import Attack

# Average tokens per attack turn (estimate)
# Based on system prompt + attack input + typical agent response
TURN_TOKENS = 1500

# Estimated cost per 1M tokens ($ for GPT-4o style models)
# This can be overridden or updated
MODEL_PRICING: Dict[str, float] = {
    "gpt-4o": 5.0, # $5 per 1M tokens (blended)
    "gpt-3.5-turbo": 0.5,
}

def estimate_scan_cost(
    attacks: List[Attack], 
    use_judge: bool = False, 
    use_adaptive: bool = False,
    model: str = "gpt-4o"
) -> Dict[str, Any]:
    """Estimate the cost of a security scan before execution.
    
    Args:
        attacks: List of attacks selected for scanning.
        use_judge: Whether an LLM judge will be used.
        use_adaptive: Whether second-turn adaptive attacks are enabled.
        model: Model name for pricing calculation.
        
    Returns:
        A dictionary with estimated token count and dollar cost.
    """
    price_per_mil = MODEL_PRICING.get(model, 5.0)
    
    total_turns = len(attacks)
    
    if use_judge:
        total_turns += len(attacks) # Judge turn per attack
        
    if use_adaptive:
        # Assume 30% of attacks will need evolution (optimistic estimate)
        total_turns += len(attacks) * 0.3 * 2 # Evolution turn + response
        
    est_tokens = total_turns * TURN_TOKENS
    est_cost = (est_tokens / 1_000_000) * price_per_mil
    
    return {
        "estimated_tokens": int(est_tokens),
        "estimated_cost_usd": round(est_cost, 4),
        "total_calls": int(total_turns)
    }
