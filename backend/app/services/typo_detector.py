
"""Detect common typing changes between submitted and trusted domains."""

from rapidfuzz import fuzz
from rapidfuzz.distance import Levenshtein

from app.services.url_parser import normalize_domain


def detect_typo(submitted_domain: str, trusted_domain: str) -> dict:
    """Compare two domains and explain their character differences."""

    if (
        not isinstance(submitted_domain, str)
        or not isinstance(trusted_domain, str)
        or not submitted_domain.strip()
        or not trusted_domain.strip()
    ):
        raise ValueError("Both domain names must be provided.")

    submitted = normalize_domain(submitted_domain)
    trusted = normalize_domain(trusted_domain)

    # Identical domains have no changes.
    if submitted == trusted:
        return {
            "submitted_domain": submitted,
            "trusted_domain": trusted,
            "edit_distance": 0,
            "changes": [],
            "similarity_score": 100.0,
            "typo_type": "exact_match",
            "changed_characters": [],
            "explanation": "The normalized domains are an exact match.",
        }

    # Calculate the minimum edits needed to transform one string.
    distance = Levenshtein.distance(submitted, trusted)

    # Check whether exactly two adjacent characters were swapped.
    # Example: "gogle" versus "google" is NOT a swap;
    # a true swap would be something like "goolge" versus "google".
    swapped_index = next(
        (
            i
            for i in range(len(submitted) - 1)
            if (
                submitted[:i]
                + submitted[i + 1]
                + submitted[i]
                + submitted[i + 2:]
                == trusted
            )
        ),
        None,
    ) if len(submitted) == len(trusted) and distance == 2 else None

    if swapped_index is not None:
        return {
            "submitted_domain": submitted,
            "trusted_domain": trusted,
            "edit_distance": distance,
            "changes": [{
                "type": "transposed_characters",
                "description": "Two adjacent characters appear to be swapped.",
                "details": [{
                    "position": swapped_index,
                    "submitted_characters": submitted[swapped_index:swapped_index + 2],
                    "trusted_characters": trusted[swapped_index:swapped_index + 2],
                }],
            }],
            "similarity_score": round(fuzz.ratio(submitted, trusted), 2),
            "typo_type": "transposed_characters",
            "changed_characters": [{
                "position": swapped_index,
                "submitted_characters": submitted[swapped_index:swapped_index + 2],
                "trusted_characters": trusted[swapped_index:swapped_index + 2],
            }],
            "explanation": (
                "Two adjacent characters appear to be swapped. "
                "Similarity is a warning signal, not proof of malicious intent."
            ),
        }

    # Get the actual minimum edit operations.
    # Each operation contains a type and the affected character positions.
    edit_operations = Levenshtein.editops(submitted, trusted)

    # Collect replacements, insertions, and deletions separately.
    replacements = []
    insertions = []
    deletions = []

    for operation in edit_operations:
        if operation.tag == "replace":
            # Replace one character in the submitted domain.
            replacements.append({
                "position": operation.src_pos,
                "submitted_character": submitted[operation.src_pos],
                "trusted_character": trusted[operation.dest_pos],
            })

        elif operation.tag == "insert":
            # A character exists in the trusted domain but is missing
            # from the submitted domain.
            insertions.append({
                "position": operation.dest_pos,
                "trusted_character": trusted[operation.dest_pos],
            })

        elif operation.tag == "delete":
            # A character exists in the submitted domain but not
            # in the trusted domain.
            deletions.append({
                "position": operation.src_pos,
                "submitted_character": submitted[operation.src_pos],
            })

    changes = []

    # A single insertion into the trusted domain means the submitted
    # domain is missing one character.
    if len(insertions) == 1 and not replacements and not deletions:
        changes.append({
            "type": "missing_character",
            "description": "The submitted domain is missing one character.",
            "details": insertions,
        })

    # A single deletion from the trusted domain means the submitted
    # domain contains one extra character.
    elif len(deletions) == 1 and not replacements and not insertions:
        changes.append({
            "type": "extra_character",
            "description": "The submitted domain contains one extra character.",
            "details": deletions,
        })

    # Only report substitutions when there are one or two replacements.
    # Many replacements are more safely described as complex changes.
    elif (
        replacements
        and len(replacements) <= 2
        and not insertions
        and not deletions
    ):
        changes.append({
            "type": "character_substitution",
            "description": (
                f"{len(replacements)} character substitution(s) detected."
            ),
            "details": replacements,
        })

    # Mixed operations or many replacements should not be described
    # as simple substitutions.
    else:
        changes.append({
            "type": "multiple_or_complex_changes",
            "description": (
                "Multiple or complex character changes were detected."
            ),
            "details": {
                "substitutions": replacements,
                "missing_characters": insertions,
                "extra_characters": deletions,
            },
        })

    changed_characters = changes[0]["details"]
    return {
        "submitted_domain": submitted,
        "trusted_domain": trusted,
        "edit_distance": distance,
        "changes": changes,
        "similarity_score": round(fuzz.ratio(submitted, trusted), 2),
        "typo_type": changes[0]["type"],
        "changed_characters": changed_characters,
        "explanation": (
            changes[0]["description"]
            + " Similarity is a warning signal, not proof of malicious intent."
        ),
    }
