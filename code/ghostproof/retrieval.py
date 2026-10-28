"""Deterministic candidate retrieval. No person merging or conflict resolution."""

from collections import defaultdict
from dataclasses import dataclass

from .facts import Fact, Identifier, make_fact
from .state import record_fields


@dataclass(frozen=True)
class Hit:
    fact: Fact
    basis: str  # IDENTIFIER, RESOURCE_HISTORY, RESOURCE_REFERENCE, REFERENCE_HISTORY
    matched_identifiers: tuple[Identifier, ...]
    linked_from: tuple[str, ...]  # identifier-matched fact locators grounding resource


class FactIndex:
    def __init__(self, facts):
        self.facts = tuple(sorted(facts, key=lambda f: (f.source_id, f.location)))
        self.by_identifier = defaultdict(list)
        self.by_resource = defaultdict(list)
        self.by_resource_id = defaultdict(list)
        for number, fact in enumerate(self.facts):
            for item in fact.identifiers: self.by_identifier[item].append(number)
            if fact.system_id and fact.resource_id:
                self.by_resource[(fact.system_id, fact.resource_id)].append(number)
                self.by_resource_id[fact.resource_id].append(number)

    def resource_history(self, system, resource, cutoff):
        return tuple(self.facts[n] for n in self.by_resource.get((system, resource), ())
                     if self.facts[n].visible_at(cutoff))

    def retrieve(self, resolution, cutoff, identities=None):
        if resolution.status != "RESOLVED": return ()
        # Shared phone/email/hash cannot seed resources belonging to other people.
        identifiers = {a.identifier for a in resolution.assertions} - set(resolution.shared_identifiers)
        seeds = defaultdict(set)
        for item in sorted(identifiers):
            for n in self.by_identifier.get(item, ()):
                if self.facts[n].visible_at(cutoff): seeds[n].add(item)
        resources = defaultdict(set)
        for n in seeds:
            fact = self.facts[n]
            if fact.system_id and fact.resource_id:
                resources[(fact.system_id, fact.resource_id)].add(fact.location)
        hits = {n: Hit(self.facts[n], "IDENTIFIER", tuple(sorted(items)), ())
                for n, items in seeds.items()}
        for resource, locators in sorted(resources.items()):
            for n in self.by_resource[resource]:
                if n not in hits and self.facts[n].visible_at(cutoff):
                    hits[n] = Hit(self.facts[n], "RESOURCE_HISTORY", (), tuple(sorted(locators)))
        references = []
        paths = {key: tuple(sorted(value)) for key, value in resources.items()}
        path_times = {key: min((self.facts[n].available_at for n in seeds
                               if (self.facts[n].system_id, self.facts[n].resource_id) == key))
                      for key in paths}
        queue = sorted(paths)
        # Only explicit resource-reference fields are edges. No prefix, name,
        # case number, nearest timestamp or arbitrary-prose matching.
        for resource in queue:
            history = self.resource_history(*resource, cutoff)
            for origin in history:
                fields = {**origin.fields, **record_fields(origin)}
                for resource_field, system_field in (("source_resource_id", "source_system"),
                                                      ("parent_resource_id", "parent_system")):
                    target_id = fields.get(resource_field)
                    if not isinstance(target_id, str) or not target_id.strip(): continue
                    target_id = target_id.strip()
                    namespace = fields.get(system_field)
                    namespace_proof = None
                    nested = record_fields(origin)
                    issue = ("Conflicting resource reference declarations" if any(
                        k in origin.fields and k in nested and origin.fields[k] != nested[k]
                        for k in (resource_field, system_field)) else "")
                    if not namespace:
                        candidates = [self.facts[n] for n in self.by_resource_id.get(target_id, ())
                                      if self.facts[n].visible_at(cutoff)]
                        systems = {f.system_id for f in candidates}
                        if len(systems) == 1:
                            namespace = next(iter(systems))
                            namespace_proof = min(candidates, key=lambda f: (f.available_at, f.source_id, f.location))
                        else:
                            issue = "Referenced resource namespace is missing or ambiguous at cutoff"
                    if namespace and not isinstance(namespace, str):
                        issue = "Referenced resource namespace is malformed"
                    target = (namespace, target_id) if not issue else None
                    target_history = self.resource_history(*target, cutoff) if target else ()

                    def foreign_owners(facts):
                        owners = set()
                        for fact in facts:
                            for item in fact.identifiers:
                                if item.kind == "user_id": owners.add(item.value)
                                if identities is not None: owners.update(identities.owners(item, cutoff))
                        return owners - set(resolution.candidates)

                    # A reference is scoped to this resolved subject, not a
                    # licence to merge an independently owned or shared record.
                    if foreign_owners(history) or foreign_owners(target_history):
                        issue = "Resource reference has conflicting or shared ownership"
                    path = tuple(dict.fromkeys(paths[resource] + (origin.location,)))
                    edge = {"field": resource_field, "source_system": resource[0],
                            "source_resource_id": resource[1], "target_system": namespace or "",
                            "target_resource_id": target_id, "source_id": origin.source_id,
                            "location": origin.location, "path": list(path),
                            "status": "BLOCKED" if issue else "LINKED",
                            "subject_scope": list(resolution.candidates),
                            "namespace_proof": ({"source_id": namespace_proof.source_id,
                                                 "location": namespace_proof.location}
                                                if namespace_proof else {})}
                    available = max(path_times[resource], origin.available_at,
                                    namespace_proof.available_at if namespace_proof else origin.available_at)
                    claim = make_fact(origin.source_id, origin.location + "/reference=" + resource_field,
                                      namespace if not issue else "",
                                      {"resource_id": target_id if not issue else "",
                                       "event_type": "RESOURCE_REFERENCE", "reference_edge": edge,
                                       "reference_issue": issue}, available, origin.observed_at,
                                      nature="CLAIM", related_locations=path)
                    references.append(Hit(claim, "RESOURCE_REFERENCE", (), path))
                    if issue or target in paths: continue
                    paths[target] = path
                    path_times[target] = available
                    queue.append(target)
                    for n in self.by_resource.get(target, ()):
                        if n not in hits and self.facts[n].visible_at(cutoff):
                            hits[n] = Hit(self.facts[n], "REFERENCE_HISTORY", (), path)
        # Keep all direct contradictions; blocked reference branches are explicit
        # diagnostics, never silently imported into another person's evidence.
        return tuple(hits[n] for n in sorted(hits)) + tuple(sorted(references,
                     key=lambda h: (h.fact.source_id, h.fact.location)))
