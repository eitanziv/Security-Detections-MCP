/**
 * Hosted MCP tool registration.
 *
 * Registers ~20 read-only detection/coverage tools on a given MCP server
 * instance. Call registerHostedTools(server) from the route handler.
 *
 * Tool input schemas are defined with Zod because mcp-handler passes them
 * through the MCP SDK's `server.tool()` API, which expects Zod shapes.
 */

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  searchDetections,
  getDetectionById,
  getRawYaml,
  listDetections,
  getStats,
  getCoverageSummary,
  getThreatProfileGaps,
  getTechniqueIntelligence,
  getTechniqueFull,
  compareSourcesForTechnique,
  listBySource,
  listBySeverity,
  listByDetectionType,
  listByMitre,
  listByMitreTactic,
  searchByFilter,
  listByAnalyticStory,
  getActorProfile,
  getActorIntelligence,
  compareActors,
  listActors,
  generateNavigatorLayer,
} from './db';

const SOURCE_ENUM = z.enum(['sigma', 'splunk_escu', 'elastic', 'kql', 'sublime', 'crowdstrike_cql']);
const SEVERITY_ENUM = z.enum(['informational', 'low', 'medium', 'high', 'critical']);
const TACTIC_ENUM = z.enum([
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
]);
const THREAT_PROFILE_ENUM = z.enum([
  'ransomware',
  'apt',
  'initial-access',
  'persistence',
  'credential-access',
  'defense-evasion',
]);

type McpTextContent = { type: 'text'; text: string };
type McpToolResult = { content: McpTextContent[]; isError?: boolean };

function json(result: unknown): McpToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
}

function err(message: string, extra?: Record<string, unknown>): McpToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify({ error: true, message, ...(extra ?? {}) }) }],
    isError: true,
  };
}

// Wrap handler to convert thrown errors into MCP tool errors with context
async function safe(name: string, fn: () => Promise<McpToolResult>): Promise<McpToolResult> {
  try {
    return await fn();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[mcp-tool:${name}] ${msg}`);
    return err(`${name} failed: ${msg}`);
  }
}

export function registerHostedTools(server: McpServer): void {
  // ─── Search & retrieval ─────────────────────────────────────────────────

  server.tool(
    'search',
    'Full-text search across all detection rules (name, description, query). Supports multi-word AND queries. Returns up to 50 detections by default.',
    {
      query: z.string().min(1).describe('Search query (words are AND-combined)'),
      limit: z.number().int().min(1).max(100).optional().describe('Max results (default 50)'),
      source_type: SOURCE_ENUM.optional().describe('Filter by detection source'),
    },
    async ({ query, limit, source_type }) =>
      safe('search', async () => {
        const results = await searchDetections(query, limit ?? 50, source_type);
        if (results.length === 0) {
          return json({
            count: 0,
            detections: [],
            hint: 'No results. Try broader keywords, remove filters, or use list_by_mitre with a technique ID.',
          });
        }
        return json({ count: results.length, detections: results });
      }),
  );

  server.tool(
    'get_by_id',
    'Get full details for a single detection by its ID (Sigma UUID or Splunk/Elastic slug).',
    {
      id: z.string().min(1).describe('Detection ID'),
    },
    async ({ id }) =>
      safe('get_by_id', async () => {
        const detection = await getDetectionById(id);
        if (!detection) return err(`Detection not found: ${id}`, { hint: 'Use search() first to find valid IDs.' });
        return json(detection);
      }),
  );

  server.tool(
    'get_raw_yaml',
    'Get the original YAML content for a detection (useful for copying the rule verbatim).',
    {
      id: z.string().min(1).describe('Detection ID'),
    },
    async ({ id }) =>
      safe('get_raw_yaml', async () => {
        const yaml = await getRawYaml(id);
        if (!yaml) return err(`No raw YAML found for: ${id}`);
        return json({ id, yaml });
      }),
  );

  server.tool(
    'list_all',
    'List detections with pagination. Prefer search() or list_by_* filters for targeted queries.',
    {
      limit: z.number().int().min(1).max(100).optional().describe('Max results (default 50, hard cap 100)'),
      offset: z.number().int().min(0).optional().describe('Offset for pagination'),
      source_type: SOURCE_ENUM.optional(),
    },
    async ({ limit, offset, source_type }) =>
      safe('list_all', async () => {
        const results = await listDetections(limit ?? 50, offset ?? 0, source_type);
        return json({ count: results.length, offset: offset ?? 0, limit: limit ?? 50, detections: results });
      }),
  );

  // ─── Stats & coverage ──────────────────────────────────────────────────

  server.tool(
    'get_stats',
    'Get summary statistics about the indexed detection corpus (total detections, per-source counts, last sync).',
    {},
    async () => safe('get_stats', async () => json(await getStats())),
  );

  server.tool(
    'get_coverage_summary',
    'Get overall MITRE ATT&CK coverage summary — total techniques, covered techniques, coverage %, breakdowns by source and tactic, weakest/strongest tactics.',
    {},
    async () => safe('get_coverage_summary', async () => json(await getCoverageSummary())),
  );

  server.tool(
    'analyze_coverage',
    'Alias for get_coverage_summary — returns the same comprehensive coverage report.',
    {},
    async () => safe('analyze_coverage', async () => json(await getCoverageSummary())),
  );

  server.tool(
    'identify_gaps',
    'Identify detection gaps for a specific threat profile (ransomware, apt, initial-access, persistence, credential-access, defense-evasion). Returns prioritized uncovered techniques.',
    {
      threat_profile: THREAT_PROFILE_ENUM.describe('Threat profile to analyze'),
    },
    async ({ threat_profile }) =>
      safe('identify_gaps', async () => json(await getThreatProfileGaps(threat_profile))),
  );

  server.tool(
    'get_technique_intelligence',
    'Deep intelligence for a single MITRE technique ID: detections by source, actors using it, related sub-techniques, coverage gaps.',
    {
      technique_id: z.string().regex(/^T\d{4}(\.\d{3})?$/).describe('MITRE technique ID like T1059 or T1059.001'),
    },
    async ({ technique_id }) =>
      safe('get_technique_intelligence', async () => json(await getTechniqueIntelligence(technique_id))),
  );

  server.tool(
    'get_technique_full',
    'Full technique detail: all covering detections (paginated), actors using it, procedures, per-source breakdown.',
    {
      technique_id: z.string().regex(/^T\d{4}(\.\d{3})?$/).describe('MITRE technique ID'),
      detection_limit: z.number().int().min(1).max(100).optional().describe('Max detections to return (default 50)'),
    },
    async ({ technique_id, detection_limit }) =>
      safe('get_technique_full', async () => json(await getTechniqueFull(technique_id, detection_limit ?? 50))),
  );

  server.tool(
    'compare_sources',
    'Cross-source comparison for a MITRE technique: how many detections does each source (Sigma, Splunk, Elastic, KQL, Sublime, CQL) have for this technique, and which sources have no coverage.',
    {
      technique_id: z.string().regex(/^T\d{4}(\.\d{3})?$/).describe('MITRE technique ID'),
    },
    async ({ technique_id }) =>
      safe('compare_sources', async () => json(await compareSourcesForTechnique(technique_id))),
  );

  server.tool(
    'generate_navigator_layer',
    'Generate a MITRE ATT&CK Navigator JSON layer showing covered techniques. Output can be pasted directly into the Navigator web app.',
    {
      name: z.string().optional().describe('Layer name shown in Navigator'),
      source_type: SOURCE_ENUM.optional().describe('Limit the layer to one source'),
    },
    async ({ name, source_type }) =>
      safe('generate_navigator_layer', async () => json(await generateNavigatorLayer({ name, sourceType: source_type }))),
  );

  // ─── Filters ───────────────────────────────────────────────────────────

  server.tool(
    'list_by_source',
    'List detections from a specific source (sigma, splunk_escu, elastic, kql, sublime, crowdstrike_cql).',
    {
      source_type: SOURCE_ENUM,
      limit: z.number().int().min(1).max(100).optional(),
    },
    async ({ source_type, limit }) =>
      safe('list_by_source', async () => json({ count: 0, source_type, detections: await listBySource(source_type, limit ?? 50) })),
  );

  server.tool(
    'list_by_severity',
    'List detections at a specific severity (informational, low, medium, high, critical).',
    {
      severity: SEVERITY_ENUM,
      limit: z.number().int().min(1).max(100).optional(),
    },
    async ({ severity, limit }) =>
      safe('list_by_severity', async () => json({ severity, detections: await listBySeverity(severity, limit ?? 50) })),
  );

  server.tool(
    'list_by_detection_type',
    'List detections by detection type (e.g., "TTP", "Anomaly", "Hunting", "Correlation").',
    {
      detection_type: z.string().min(1).describe('Detection type label'),
      limit: z.number().int().min(1).max(100).optional(),
    },
    async ({ detection_type, limit }) =>
      safe('list_by_detection_type', async () =>
        json({ detection_type, detections: await listByDetectionType(detection_type, limit ?? 50) }),
      ),
  );

  server.tool(
    'list_by_mitre',
    'List detections that reference a specific MITRE technique ID (via the detection_techniques junction table).',
    {
      technique_id: z.string().regex(/^T\d{4}(\.\d{3})?$/).describe('MITRE technique ID like T1059.001'),
      limit: z.number().int().min(1).max(100).optional(),
    },
    async ({ technique_id, limit }) =>
      safe('list_by_mitre', async () => json({ technique_id, detections: await listByMitre(technique_id, limit ?? 50) })),
  );

  server.tool(
    'list_by_mitre_tactic',
    'List detections that map to a specific MITRE tactic (e.g., credential-access, defense-evasion).',
    {
      tactic: TACTIC_ENUM,
      limit: z.number().int().min(1).max(100).optional(),
    },
    async ({ tactic, limit }) =>
      safe('list_by_mitre_tactic', async () => json({ tactic, detections: await listByMitreTactic(tactic, limit ?? 50) })),
  );

  server.tool(
    'list_by_cve',
    'Find detections that reference a specific CVE ID.',
    {
      cve: z.string().regex(/^CVE-\d{4}-\d{4,7}$/).describe('CVE identifier like CVE-2024-12345'),
      limit: z.number().int().min(1).max(50).optional(),
    },
    async ({ cve, limit }) =>
      safe('list_by_cve', async () => json(await searchByFilter('cve', cve, limit ?? 20))),
  );

  server.tool(
    'list_by_process_name',
    'Find detections that monitor a specific process name (e.g., rundll32.exe, powershell.exe).',
    {
      process_name: z.string().min(1).describe('Process executable name'),
      limit: z.number().int().min(1).max(50).optional(),
    },
    async ({ process_name, limit }) =>
      safe('list_by_process_name', async () => json(await searchByFilter('process_name', process_name, limit ?? 20))),
  );

  server.tool(
    'list_by_data_source',
    'Find detections that require a specific data source (e.g., "Sysmon", "Windows Event Log", "Process Creation").',
    {
      data_source: z.string().min(1).describe('Data source name'),
      limit: z.number().int().min(1).max(50).optional(),
    },
    async ({ data_source, limit }) =>
      safe('list_by_data_source', async () => json(await searchByFilter('data_source', data_source, limit ?? 20))),
  );

  server.tool(
    'list_by_analytic_story',
    'List detections that belong to a Splunk Analytic Story (e.g., "Ransomware", "Cloud Federated Credential Abuse").',
    {
      story: z.string().min(1).describe('Analytic story name'),
      limit: z.number().int().min(1).max(100).optional(),
    },
    async ({ story, limit }) =>
      safe('list_by_analytic_story', async () =>
        json({ story, detections: await listByAnalyticStory(story, limit ?? 50) }),
      ),
  );

  // ─── Threat actors ─────────────────────────────────────────────────────

  server.tool(
    'list_actors',
    'List or search MITRE ATT&CK threat actors. Pass a query to search by name or alias.',
    {
      query: z.string().optional().describe('Search term (matches name and aliases)'),
      limit: z.number().int().min(1).max(200).optional(),
    },
    async ({ query, limit }) =>
      safe('list_actors', async () => json({ actors: await listActors(limit ?? 50, query) })),
  );

  server.tool(
    'get_actor_profile',
    'Get a full profile for a threat actor: description, aliases, technique list, and detection coverage %.',
    {
      actor_name: z.string().min(1).describe('Threat actor name (e.g., "APT29", "FIN7")'),
    },
    async ({ actor_name }) =>
      safe('get_actor_profile', async () => json(await getActorProfile(actor_name))),
  );

  server.tool(
    'analyze_actor_coverage',
    'Deep intelligence about a threat actor: per-tactic coverage breakdown, covered techniques with detection counts, and all uncovered technique gaps.',
    {
      actor_name: z.string().min(1).describe('Threat actor name'),
    },
    async ({ actor_name }) =>
      safe('analyze_actor_coverage', async () => json(await getActorIntelligence(actor_name))),
  );

  server.tool(
    'compare_actor_coverage',
    'Compare two or more threat actors side-by-side: total techniques, coverage %, shared gaps, unique gaps.',
    {
      actor_names: z.array(z.string().min(1)).min(2).max(5).describe('Between 2 and 5 actor names to compare'),
    },
    async ({ actor_names }) =>
      safe('compare_actor_coverage', async () => json(await compareActors(actor_names))),
  );
}
