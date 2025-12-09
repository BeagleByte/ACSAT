"""
Enhanced POC Hunter Agent that uses:
1. DuckDuckGo for web searching (no API key needed!)
2. Ollama for intelligent analysis and filtering
3. Multiple search strategies to find the best POCs

This agent:
- Uses Ollama to understand CVE details and search strategy
- Searches GitHub, ExploitDB, Metasploit via DuckDuckGo
- Uses Ollama to analyze and rank results by relevance
- Filters out false positives using LLM reasoning
"""

import logging
import re
from datetime import datetime
from typing import List, Dict, Optional
from Database.database import CVE, POC, AgentRun
from sqlalchemy. orm import Session
from sqlalchemy import desc
from agno.agent import Agent
from agno.models. ollama import Ollama
from agno.tools.website import WebsiteTools
from ddgs import DDGS  # DuckDuckGo search library
import time

logger = logging.getLogger(__name__)

class POCHunterAgent:
    """
    Advanced POC Hunter Agent using Ollama + DuckDuckGo.

    How it works:
    1. Takes a CVE and uses Ollama to understand it better
    2. Generates multiple search queries with Ollama help
    3. Searches using DuckDuckGo (no API keys needed!)
    4. Uses Ollama to analyze results and rank relevance
    5. Stores validated results in database
    """

    def __init__(self, model_name: str = "mistral"):
        """
        Initialize POC hunter with Ollama + DuckDuckGo.

        Args:
            model_name (str): Ollama model (mistral, llama2, neural-chat, etc.)
        """
        self. model_name = model_name

        # Initialize Ollama-based Agno Agent for analysis
        self.agent = Agent(
            name="poc-hunter",
            model=Ollama(
                model_id=model_name,
                base_url="http://localhost:11434",
                timeout=120
            ),
            tools=[WebsiteTools()],
            instructions="""
            You are an expert Proof of Concept (POC) and exploit researcher.
            Your job is to:  
            
            1. UNDERSTAND CVEs: 
               - Analyze CVE details (description, affected products, severity)
               - Identify key technical terms and affected software
            
            2. GENERATE SEARCH QUERIES:
               - Create targeted search queries for finding POCs
               - Include:  CVE ID, software name, "exploit", "poc", "github"
               - Example: "CVE-2024-1234 OpenSSL exploit github"
            
            3. ANALYZE SEARCH RESULTS:
               - Evaluate which results are legitimate POCs vs.  false positives
               - Score relevance (0-100) based on:
                 * Is it actually related to this CVE?
                 * Is it a working POC/exploit?
                 * How many stars/forks?  (quality indicator)
                 * Is it from official sources (rapid7, etc.)?
            
            4. FILTER RESULTS: 
               - Remove spam, scams, and unrelated results
               - Prioritize verified, high-quality POCs
               - Flag suspicious or potentially malicious content
            
            For each POC found, extract:
            - Title and description
            - Direct link
            - Source type (github, exploit-db, metasploit, etc.)
            - Programming language
            - Relevance score (0-100)
            - Verification status
            """,
            markdown=True
        )

        # Initialize DuckDuckGo searcher
        self.ddgs = DDGS()

    def run(self, db: Session, cve_ids: Optional[List[str]] = None,
            limit: int = 20, max_results_per_cve: int = 10) -> dict:
        """
        Main execution method for POC hunting using Ollama + DuckDuckGo.

        Args:
            db (Session): Database session
            cve_ids (List[str]): Specific CVE IDs to search (if None, searches recent CVEs)
            limit (int): Max CVEs to process
            max_results_per_cve (int): Max search results per CVE

        Returns:
            dict:  Execution results with statistics
        """
        run_record = AgentRun(agent_name="poc_hunter", status="running")
        db.add(run_record)
        db.commit()

        try:
            logger.info(f"🔍 Starting POC Hunter with Ollama ({self.model_name}) + DuckDuckGo...")

            # Get CVEs to search for
            if cve_ids:
                cves_to_search = db.query(CVE).filter(CVE.cve_id.in_(cve_ids)).limit(limit).all()
            else:
                # Get recent CVEs without POCs
                cves_with_pocs = db.query(CVE. cve_id).join(POC).distinct().all()
                searched_cve_ids = [c[0] for c in cves_with_pocs]

                cves_to_search = db. query(CVE).filter(
                    ~CVE.cve_id. in_(searched_cve_ids) if searched_cve_ids else True
                ).order_by(desc(CVE. published_date)).limit(limit).all()

            logger.info(f"🎯 Hunting POCs for {len(cves_to_search)} CVEs (max {max_results_per_cve} results each)")

            pocs_found = 0
            cves_checked = 0

            # Search for POCs for each CVE
            for idx, cve in enumerate(cves_to_search, 1):
                try:
                    logger.info(f"\n[{idx}/{len(cves_to_search)}] Searching: {cve.cve_id}")
                    logger.info(f"    Title: {cve.title[: 60]}")
                    logger.info(f"    Severity: {cve.severity}")

                    # Use Ollama to search and analyze
                    results = self._hunt_poc_with_ollama(cve, db, max_results_per_cve)
                    pocs_found += len(results)
                    cves_checked += 1

                    if results:
                        logger.info(f"    ✅ Found {len(results)} POCs")
                    else:
                        logger.info(f"    ❌ No POCs found")

                    # Rate limiting (be respectful to DuckDuckGo)
                    time.sleep(2)

                except Exception as e:
                    logger.warning(f"⚠️  Error searching for {cve.cve_id}: {e}")
                    cves_checked += 1

            # Update run record
            run_record.status = "success"
            run_record.items_collected = pocs_found
            run_record.items_processed = cves_checked
            run_record.completed_at = datetime.utcnow()
            db.commit()

            logger. info(f"\n{'='*60}")
            logger.info(f"✅ POC Hunting Completed!")
            logger.info(f"   - CVEs Searched: {cves_checked}")
            logger.info(f"   - POCs Found: {pocs_found}")
            logger.info(f"   - Avg POCs/CVE: {pocs_found / max(cves_checked, 1):.1f}")
            logger.info(f"{'='*60}\n")

            return {
                "status": "success",
                "pocs_found": pocs_found,
                "cves_searched": cves_checked,
                "model_used": self.model_name
            }

        except Exception as e:
            logger.error(f"❌ POC hunting failed: {e}")
            run_record.status = "failed"
            run_record.error_message = str(e)
            run_record.completed_at = datetime.utcnow()
            db.commit()
            return {"status": "failed", "error":  str(e)}

    def _hunt_poc_with_ollama(self, cve: CVE, db: Session,
                             max_results:  int = 10) -> List[Dict]:
        """
        Hunt for POCs using Ollama + DuckDuckGo for a specific CVE.

        Process:
        1. Use Ollama to generate smart search queries
        2. Search with DuckDuckGo using those queries
        3. Use Ollama to analyze and rank results
        4. Store best results in database

        Args:
            cve (CVE): CVE object to search for
            db (Session): Database session
            max_results (int): Max POCs to find per CVE

        Returns:
            list: List of POC dictionaries added to database
        """
        pocs_found = []
        cve_id = cve.cve_id

        logger.info(f"    🧠 Using Ollama to generate search strategy...")

        # Step 1: Use Ollama to generate smart search queries
        search_queries = self._generate_search_queries_with_ollama(cve)

        logger.info(f"    🔍 Generated {len(search_queries)} search queries")

        # Step 2: Search each query with DuckDuckGo
        all_search_results = []
        for query in search_queries:
            logger.info(f"       → Searching: '{query}'")

            try:
                # Search with DuckDuckGo
                results = self._duckduckgo_search(query, max_results=5)

                if results:
                    logger.info(f"         Found {len(results)} results")
                    all_search_results.extend(results)
                else:
                    logger.info(f"         No results found")

                # Rate limiting
                time.sleep(1)

            except Exception as e:
                logger.warning(f"       ⚠️  Search error: {e}")

        logger.info(f"    📊 Total results found: {len(all_search_results)}")

        if not all_search_results:
            logger.info(f"    ℹ️  No results to analyze")
            return pocs_found

        # Step 3: Use Ollama to analyze and filter results
        logger.info(f"    🧠 Using Ollama to analyze and rank results...")

        analyzed_results = self._analyze_results_with_ollama(cve, all_search_results)

        logger.info(f"    ✨ Ollama ranked {len(analyzed_results)} relevant results")

        # Step 4: Store best results in database
        for result in analyzed_results[: max_results]:
            try:
                poc = self._create_poc_from_result(cve_id, result, db)
                if poc:
                    pocs_found.append(poc)
                    logger.info(f"       ✅ Added:  {result. get('title', 'Unknown')}")

            except Exception as e:
                logger.warning(f"       ⚠️  Error storing POC: {e}")

        return pocs_found

    def _generate_search_queries_with_ollama(self, cve: CVE) -> List[str]:
        """
        Use Ollama to generate intelligent search queries for a CVE.

        Instead of just searching for the CVE ID, Ollama analyzes:
        - What software is affected?
        - What type of vulnerability is it?
        - What terms would POCs use?

        Then generates targeted queries.
        """
        prompt = f"""
Given this CVE, generate 3-5 specific search queries to find Proof of Concepts (POCs) and exploits.

CVE Information:
- ID: {cve.cve_id}
- Title: {cve.title}
- Description: {cve.description[: 500] if cve.description else 'N/A'}
- Severity:  {cve.severity}
- Affected Products: {', '.join(cve.affected_products[: 5]) if cve.affected_products else 'Unknown'}

Generate search queries that would find: 
1. GitHub POC repositories
2. ExploitDB exploits
3. Metasploit modules
4. Security blog posts with POCs

Format: Return ONLY the queries, one per line, no numbering. 
Example format:
{cve. cve_id} poc github
{cve.cve_id} exploit
{cve.cve_id} OpenSSL proof of concept
"""

        try:
            # Call Ollama directly via the model
            response = self.agent.model.response(prompt)

            if response:
                # Parse queries from response
                queries = [q.strip() for q in response.split('\n') if q.strip()]
                # Add default query if none generated
                if not queries:
                    queries = [f"{cve.cve_id} poc", f"{cve.cve_id} exploit"]

                return queries[: 5]  # Return max 5 queries

        except Exception as e:
            logger.warning(f"Error generating queries with Ollama: {e}")

        # Fallback queries
        return [
            f"{cve.cve_id} poc",
            f"{cve.cve_id} exploit",
            f"{cve.cve_id} github",
        ]

    def _duckduckgo_search(self, query: str, max_results: int = 5) -> List[Dict]:
        """
        Search DuckDuckGo for POC-related content.

        Args:
            query (str): Search query
            max_results (int): Max results to return

        Returns:
            list:  Search results with title, URL, description
        """
        try:
            # Use DDGS library for DuckDuckGo searches
            # Returns: [{"title": ".. .", "body": ".. .", "href": "..."}, ...]
            results = self.ddgs.text(query, max_results=max_results)

            # Convert to our format
            formatted_results = []
            for result in results:
                formatted_results.append({
                    'title': result.get('title', ''),
                    'url': result.get('href', ''),
                    'description': result.get('body', ''),
                    'source': 'duckduckgo'
                })

            return formatted_results

        except Exception as e:
            logger.warning(f"DuckDuckGo search error: {e}")
            return []

    def _analyze_results_with_ollama(self, cve: CVE, results: List[Dict]) -> List[Dict]:
        """
        Use Ollama to analyze and rank search results for relevance.

        Ollama evaluates:
        - Is this actually a POC for this CVE?
        - How confident are we (0-100)?
        - What type of POC is it?
        - Is it likely legitimate vs.  spam/malware?

        Args:
            cve (CVE): The CVE being analyzed
            results (List[Dict]): Search results from DuckDuckGo

        Returns:
            list:  Ranked and analyzed results
        """

        # Limit to avoid huge prompts
        results_to_analyze = results[:20]

        # Format results for Ollama
        results_text = "\n".join([
            f"{i+1}. Title: {r['title']}\n   URL: {r['url']}\n   Desc: {r['description'][: 200]}"
            for i, r in enumerate(results_to_analyze)
        ])

        prompt = f"""
You are an expert security researcher.  Analyze these search results for POCs related to {cve.cve_id}. 

CVE:  {cve.cve_id}
Severity: {cve.severity}
Description: {cve.description[:300] if cve.description else 'N/A'}

Search Results:
{results_text}

For EACH result, determine:
1. Is it actually a POC/exploit for this CVE?  (yes/no)
2. Relevance score:  0-100 (higher = more relevant)
3. Type: github_repo, exploit-db, metasploit, blog, tool, etc. 
4. Language: Python, JavaScript, Ruby, Bash, etc.  (if detectable)
5. Confidence: How confident are you? (low/medium/high)

Format your response as JSON, example:
[
  {{"url": "https://...", "relevant": true, "score": 95, "type": "github_repo", "language": "Python", "confidence": "high"}},
  {{"url": "https://...", "relevant": false, "score": 10, "type": "blog", "confidence": "medium"}}
]

ONLY return valid JSON, no other text.
"""

        try:
            response = self.agent.model.response(prompt)

            # Try to parse JSON response
            import json

            # Extract JSON from response
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())

                # Merge analysis with original results
                analyzed = []
                for result in results_to_analyze:
                    for analysis_item in analysis:
                        if analysis_item.get('url') == result['url']:
                            result.update(analysis_item)
                            if result. get('relevant'):
                                analyzed.append(result)
                            break

                # Sort by relevance score
                analyzed.sort(key=lambda x: x. get('score', 0), reverse=True)

                return analyzed

        except Exception as e:
            logger.warning(f"Error analyzing results with Ollama: {e}")

        # Fallback: Return results as-is with default scores
        return [{
            **r,
            'relevant': True,
            'score': 50,
            'type': 'unknown',
            'confidence': 'low'
        } for r in results_to_analyze]

    def _create_poc_from_result(self, cve_id: str, result: Dict,
                               db: Session) -> Optional[POC]:
        """
        Create a POC database record from an analyzed search result.

        Args:
            cve_id (str): CVE ID
            result (Dict): Analyzed search result from Ollama
            db (Session): Database session

        Returns:
            POC object or None if creation fails
        """

        url = result.get('url', '')

        # Skip empty URLs
        if not url:
            return None

        # Check if POC already exists
        existing = db.query(POC).filter(POC.url == url).first()
        if existing:
            return None

        # Determine source from URL
        source = self._determine_source(url)

        # Extract type and language
        poc_type = result.get('type', 'unknown')
        language = result.get('language', 'Unknown')

        # Create POC record
        poc = POC(
            cve_id=cve_id,
            found=True,
            title=result.get('title', 'POC')[: 255],
            description=result.get('description', '')[: 1000],
            url=url,
            source=source,
            poc_type=poc_type,
            language=language,
            verified=result.get('confidence') in ['high', 'verified'],
            stars=0,  # Will be updated later for GitHub
            metadata={
                'ollama_relevance_score': result.get('score', 0),
                'ollama_confidence': result.get('confidence', 'unknown'),
                'search_source': 'duckduckgo'
            }
        )

        db.add(poc)
        db.commit()

        return poc

    def _determine_source(self, url: str) -> str:
        """Determine source of POC from URL"""
        url_lower = url.lower()

        if 'github.com' in url_lower:
            return 'github'
        elif 'exploit-db' in url_lower or 'exploitdb' in url_lower:
            return 'exploit-db'
        elif 'metasploit' in url_lower or 'rapid7' in url_lower:
            return 'metasploit'
        elif 'nuclei' in url_lower:
            return 'nuclei'
        elif 'poc. in' in url_lower or 'poc-in' in url_lower:
            return 'poc-in'
        elif 'packetstorm' in url_lower:
            return 'packetstorm'
        else:
            return 'other'