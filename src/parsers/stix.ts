/**
 * MITRE ATT&CK STIX 2.1 Bundle Parser
 *
 * Parses enterprise-attack.json to populate:
 * - attack_techniques: Full technique catalog with metadata
 * - attack_actors: Threat actor/intrusion-set catalog
 * - attack_software: Malware and tool catalog
 * - actor_techniques: Actor → Technique relationships
 * - software_techniques: Software → Technique relationships
 * - technique_tactics: Authoritative technique → tactic mappings
 *
 * Zero npm dependencies — pure JSON parsing.
 */

import { readFileSync } from 'fs';
import { getDb } from '../db/connection.js';

// =============================================================================
// TYPES
// =============================================================================

export interface StixIngestResult {
  techniques: number;
  actors: number;
  software: number;
  actor_technique_links: number;
  software_technique_links: number;
  technique_tactic_links: number;
}

interface StixObject {
  id: string;
  type: string;
  name?: string;
  description?: string;
  created?: string;
  modified?: string;
  revoked?: boolean;
  x_mitre_deprecated?: boolean;
  x_mitre_is_subtechnique?: boolean;
  x_mitre_platforms?: string[];
  x_mitre_data_sources?: string[];
  external_references?: Array<{
    source_name: string;
    external_id?: string;
    url?: string;
  }>;
  kill_chain_phases?: Array<{
    kill_chain_name: string;
    phase_name: string;
  }>;
  aliases?: string[];
  relationship_type?: string;
  source_ref?: string;
  target_ref?: string;
}

interface StixBundle {
  type: string;
  id: string;
  objects: StixObject[];
}

// =============================================================================
// HELPERS
// =============================================================================

/**
 * Extract the ATT&CK ID (e.g., T1059.001) from a STIX object's external references.
 */
function getAttackId(obj: StixObject): string | null {
  if (!obj.external_references) return null;
  for (const ref of obj.external_references) {
    if (ref.source_name === 'mitre-attack' && ref.external_id) {
      return ref.external_id;
    }
  }
  return null;
}

/**
 * Extract the ATT&CK URL from external references.
 */
function getAttackUrl(obj: StixObject): string | null {
  if (!obj.external_references) return null;
  for (const ref of obj.external_references) {
    if (ref.source_name === 'mitre-attack' && ref.url) {
      return ref.url;
    }
  }
  return null;
}

/**
 * Get parent technique ID from a sub-technique ID (e.g., T1059.001 → T1059).
 */
function getParentTechniqueId(techniqueId: string): string | null {
  const dotIndex = techniqueId.indexOf('.');
  if (dotIndex === -1) return null;
  return techniqueId.substring(0, dotIndex);
}

/**
 * Normalize STIX tactic phase names to the project's convention.
 * STIX uses phase_name like "initial-access" which already matches.
 */
function normalizeTactic(phaseName: string): string {
  return phaseName.toLowerCase().replace(/ /g, '-');
}

// =============================================================================
// MAIN INGEST FUNCTION
// =============================================================================

/**
 * Parse and ingest a MITRE ATT&CK STIX 2.1 bundle into the database.
 *
 * @param stixPath Path to enterprise-attack.json
 * @returns Counts of ingested entities
 */
export function ingestStixBundle(stixPath: string): StixIngestResult {
  const database = getDb();

  // Read and parse the STIX bundle
  const raw = readFileSync(stixPath, 'utf-8');
  const bundle: StixBundle = JSON.parse(raw);

  if (!bundle.objects || !Array.isArray(bundle.objects)) {
    throw new Error('Invalid STIX bundle: missing objects array');
  }

  // =========================================================================
  // PASS 1: Build lookup maps and categorize objects
  // =========================================================================

  const stixIdToAttackId = new Map<string, string>();  // STIX ID → T1059.001
  const stixIdToType = new Map<string, string>();       // STIX ID → object type

  const techniques: StixObject[] = [];
  const actors: StixObject[] = [];
  const software: StixObject[] = [];
  const relationships: StixObject[] = [];

  for (const obj of bundle.objects) {
    // Skip revoked or deprecated objects
    if (obj.revoked === true || obj.x_mitre_deprecated === true) continue;

    switch (obj.type) {
      case 'attack-pattern': {
        const attackId = getAttackId(obj);
        if (attackId) {
          stixIdToAttackId.set(obj.id, attackId);
          stixIdToType.set(obj.id, 'technique');
          techniques.push(obj);
        }
        break;
      }
      case 'intrusion-set': {
        stixIdToType.set(obj.id, 'actor');
        actors.push(obj);
        break;
      }
      case 'malware':
      case 'tool': {
        stixIdToType.set(obj.id, 'software');
        software.push(obj);
        break;
      }
      case 'relationship': {
        if (obj.relationship_type === 'uses') {
          relationships.push(obj);
        }
        break;
      }
    }
  }

  // =========================================================================
  // PASS 2: Insert entities in a transaction
  // =========================================================================

  const result: StixIngestResult = {
    techniques: 0,
    actors: 0,
    software: 0,
    actor_technique_links: 0,
    software_technique_links: 0,
    technique_tactic_links: 0,
  };

  const insertTransaction = database.transaction(() => {
    // --- Techniques ---
    const techStmt = database.prepare(`
      INSERT OR REPLACE INTO attack_techniques
      (technique_id, name, description, platforms, data_sources, is_subtechnique, parent_technique_id, url)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    // Clear existing STIX-sourced technique_tactics before re-inserting
    database.prepare("DELETE FROM technique_tactics WHERE source = 'stix'").run();

    const ttStmt = database.prepare(
      "INSERT OR REPLACE INTO technique_tactics (technique_id, tactic_name, source) VALUES (?, ?, 'stix')"
    );

    for (const tech of techniques) {
      const attackId = getAttackId(tech)!;
      const isSubtechnique = tech.x_mitre_is_subtechnique === true ? 1 : 0;
      const parentId = getParentTechniqueId(attackId);

      techStmt.run(
        attackId,
        tech.name || attackId,
        tech.description || null,
        tech.x_mitre_platforms ? JSON.stringify(tech.x_mitre_platforms) : null,
        tech.x_mitre_data_sources ? JSON.stringify(tech.x_mitre_data_sources) : null,
        isSubtechnique,
        parentId,
        getAttackUrl(tech),
      );
      result.techniques++;

      // Insert technique → tactic mappings from kill_chain_phases
      if (tech.kill_chain_phases) {
        for (const phase of tech.kill_chain_phases) {
          if (phase.kill_chain_name === 'mitre-attack') {
            ttStmt.run(attackId, normalizeTactic(phase.phase_name));
            result.technique_tactic_links++;
          }
        }
      }
    }

    // --- Actors (Intrusion Sets) ---
    const actorStmt = database.prepare(`
      INSERT OR REPLACE INTO attack_actors
      (actor_id, name, aliases, description, external_references, created, modified)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    for (const actor of actors) {
      actorStmt.run(
        actor.id,
        actor.name || 'Unknown',
        actor.aliases ? JSON.stringify(actor.aliases) : null,
        actor.description || null,
        actor.external_references ? JSON.stringify(actor.external_references) : null,
        actor.created || null,
        actor.modified || null,
      );
      result.actors++;
    }

    // --- Software (Malware + Tools) ---
    const swStmt = database.prepare(`
      INSERT OR REPLACE INTO attack_software
      (software_id, name, software_type, description, platforms, aliases)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    for (const sw of software) {
      swStmt.run(
        sw.id,
        sw.name || 'Unknown',
        sw.type,  // 'malware' or 'tool'
        sw.description || null,
        sw.x_mitre_platforms ? JSON.stringify(sw.x_mitre_platforms) : null,
        sw.aliases ? JSON.stringify(sw.aliases) : null,
      );
      result.software++;
    }

    // =====================================================================
    // PASS 3: Process "uses" relationships
    // =====================================================================

    const actorTechStmt = database.prepare(
      'INSERT OR REPLACE INTO actor_techniques (actor_id, technique_id, description) VALUES (?, ?, ?)'
    );
    const swTechStmt = database.prepare(
      'INSERT OR REPLACE INTO software_techniques (software_id, technique_id, description) VALUES (?, ?, ?)'
    );

    for (const rel of relationships) {
      if (!rel.source_ref || !rel.target_ref) continue;

      const sourceType = stixIdToType.get(rel.source_ref);
      const targetAttackId = stixIdToAttackId.get(rel.target_ref);

      // Only process relationships where the target is a known technique
      if (!targetAttackId) continue;

      // Truncate description to avoid storing massive text
      const desc = rel.description
        ? rel.description.substring(0, 2000)
        : null;

      if (sourceType === 'actor') {
        actorTechStmt.run(rel.source_ref, targetAttackId, desc);
        result.actor_technique_links++;
      } else if (sourceType === 'software') {
        swTechStmt.run(rel.source_ref, targetAttackId, desc);
        result.software_technique_links++;
      }
    }
  });

  insertTransaction();

  return result;
}
