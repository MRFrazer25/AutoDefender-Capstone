"""Playbook Editor Page - Create and modify response playbooks."""

import json
import logging
import os
import re

import streamlit as st
from pathlib import Path
from typing import Dict, List, Any

from streamlit_pages.session_config import record
from utils.display import md_escape

logger = logging.getLogger(__name__)

PLAYBOOK_FILE = Path("playbooks/playbooks.json")

ACTION_TYPES = [
    "SURICATA_DROP_RULE",
    "LOG",
    "WEBHOOK_NOTIFY"
]

SEVERITY_OPTIONS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

PLAYBOOK_ID_PATTERN = re.compile(r"[a-z0-9_]{1,50}")


def load_playbooks() -> List[Dict[str, Any]]:
    """Load playbooks from JSON file."""
    if not PLAYBOOK_FILE.exists():
        return []
    
    try:
        with open(PLAYBOOK_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        logger.exception("Error loading playbooks")
        st.error("Could not load playbooks. Check the server log for details.")
        return []


def save_playbooks(playbooks: List[Dict[str, Any]]) -> bool:
    """Save playbooks to JSON file."""
    try:
        PLAYBOOK_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Write a temporary file and swap it in so a crash can't leave a half-written file
        temp_file = PLAYBOOK_FILE.with_suffix(".json.tmp")
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(playbooks, f, indent=2)
        os.replace(temp_file, PLAYBOOK_FILE)
        return True
    except Exception:
        logger.exception("Error saving playbooks")
        st.error("Could not save playbooks. Check the server log for details.")
        return False


def validate_playbook(playbook: Dict[str, Any]) -> tuple[bool, str]:
    """Validate playbook structure and limit sizes."""
    if not PLAYBOOK_ID_PATTERN.fullmatch(playbook.get('id') or ''):
        return False, "Playbook ID must be 1-50 lowercase letters, digits, or underscores"
    
    name = playbook.get('name') or ''
    if not name.strip() or len(name) > 100:
        return False, "Playbook name is required (up to 100 characters)"
    
    conditions = playbook.get('conditions') or {}
    severities = conditions.get('severity') or []
    if not severities or any(s not in SEVERITY_OPTIONS for s in severities):
        return False, "At least one valid severity level is required"
    
    keywords = conditions.get('keywords') or []
    if len(keywords) > 20 or any(len(k) > 50 for k in keywords):
        return False, "Use up to 20 keywords of up to 50 characters each"
    
    steps = playbook.get('steps') or []
    if not steps or len(steps) > 10:
        return False, "A playbook needs 1 to 10 action steps"
    
    for step in steps:
        if step.get('type') not in ACTION_TYPES:
            return False, "Each step needs a valid action type"
        description = step.get('description') or ''
        if not description.strip() or len(description) > 200:
            return False, "Each step needs a description (up to 200 characters)"
    
    return True, ""


def show():
    """Display the playbook editor interface."""
    st.title("Playbook Editor")
    st.markdown("Create and customize automated response workflows for detected threats.")
    
    playbooks = load_playbooks()
    
    # Sidebar for playbook selection
    st.sidebar.header("Playbooks")
    
    if 'selected_playbook_idx' not in st.session_state:
        st.session_state.selected_playbook_idx = None
    
    if 'creating_new' not in st.session_state:
        st.session_state.creating_new = False
    
    # List existing playbooks
    for idx, pb in enumerate(playbooks):
        if st.sidebar.button(f"[Playbook] {md_escape(pb['name'])}", key=f"pb_{idx}"):
            st.session_state.selected_playbook_idx = idx
            st.session_state.creating_new = False
    
    if st.sidebar.button("+ Create New Playbook"):
        st.session_state.creating_new = True
        st.session_state.selected_playbook_idx = None
    
    # Main editor area
    if st.session_state.creating_new:
        st.subheader("Create New Playbook")
        edit_playbook_form(None, playbooks)
    
    elif st.session_state.selected_playbook_idx is not None:
        idx = st.session_state.selected_playbook_idx
        if idx < len(playbooks):
            st.subheader(f"Edit: {playbooks[idx]['name']}")
            edit_playbook_form(playbooks[idx], playbooks, idx)
    
    else:
        st.info("Select a playbook from the sidebar to edit, or create a new one.")
        
        # Display summary
        if playbooks:
            st.markdown("### Current Playbooks")
            for pb in playbooks:
                with st.expander(f"{md_escape(pb['name'])} ({md_escape(pb['id'])})"):
                    st.write(f"**Triggers on:** {', '.join(pb['conditions']['severity'])} severity")
                    if pb['conditions'].get('keywords'):
                        st.write(f"**Keywords:** {md_escape(', '.join(pb['conditions']['keywords']))}")
                    st.write(f"**Actions:** {len(pb['steps'])} steps")
                    for i, step in enumerate(pb['steps'], 1):
                        st.text(f"{i}. {step['type']}: {step['description']}")


def edit_playbook_form(playbook: Dict[str, Any] | None, all_playbooks: List[Dict[str, Any]], idx: int | None = None):
    """Display form for editing or creating a playbook."""
    
    # Initialize with existing values or defaults
    if playbook:
        default_id = playbook['id']
        default_name = playbook['name']
        default_severities = playbook['conditions']['severity']
        default_keywords = ', '.join(playbook['conditions'].get('keywords', []))
        default_steps = playbook['steps']
    else:
        default_id = ""
        default_name = ""
        default_severities = []
        default_keywords = ""
        default_steps = []
    
    # Initialize steps in session state (outside form)
    form_key = f"playbook_form_{idx if idx is not None else 'new'}"
    if f'editing_steps_{form_key}' not in st.session_state:
        st.session_state[f'editing_steps_{form_key}'] = default_steps.copy() if default_steps else []
    
    # Step management UI (outside form)
    st.markdown("#### Action Steps")
    st.caption("Define the sequence of actions to execute when this playbook triggers.")
    
    # Display current steps
    for i, step in enumerate(st.session_state[f'editing_steps_{form_key}']):
        col1, col2, col3 = st.columns([2, 5, 1])
        with col1:
            st.text(step['type'])
        with col2:
            st.text(step['description'])
        with col3:
            if st.button("[X]", key=f"del_step_{form_key}_{i}"):
                st.session_state[f'editing_steps_{form_key}'].pop(i)
                st.rerun()
    
    # Add new step section
    st.markdown("**Add Action Step**")
    col1, col2 = st.columns([1, 2])
    with col1:
        new_step_type = st.selectbox(
            "Action Type",
            options=ACTION_TYPES,
            key=f"new_step_type_{form_key}",
            help="SURICATA_DROP_RULE: Create Suricata rule | LOG: Record event | WEBHOOK_NOTIFY: Send alert"
        )
    with col2:
        new_step_desc = st.text_input(
            "Description",
            key=f"new_step_desc_{form_key}",
            help="What this step does. Example: Block SSH source IP in Suricata"
        )
    
    if st.button("+ Add Step", key=f"add_step_{form_key}"):
        if new_step_type and new_step_desc:
            st.session_state[f'editing_steps_{form_key}'].append({
                'type': new_step_type,
                'description': new_step_desc
            })
            st.rerun()
    
    with st.form("playbook_form"):
        st.markdown("#### Basic Information")
        
        pb_id = st.text_input(
            "Playbook ID",
            value=default_id,
            help="Unique identifier (lowercase, underscores only). Example: ssh_bruteforce",
            disabled=(playbook is not None)  # Can't change ID of existing playbook
        )
        
        pb_name = st.text_input(
            "Playbook Name",
            value=default_name,
            help="Human-readable name. Example: Critical SSH Brute Force Response"
        )
        
        st.markdown("#### Trigger Conditions")
        
        severities = st.multiselect(
            "Severity Levels",
            options=SEVERITY_OPTIONS,
            default=default_severities,
            help="Playbook triggers when threat matches any of these severities"
        )
        
        keywords_input = st.text_input(
            "Keywords (comma-separated)",
            value=default_keywords,
            help="Optional. Playbook only triggers if threat description contains these keywords. Example: ssh, brute, force"
        )
        
        # Form submission buttons
        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            save_btn = st.form_submit_button("[Save] Save Playbook", type="primary")
        with col2:
            if playbook is not None:
                delete_btn = st.form_submit_button("[Delete] Delete", type="secondary")
            else:
                delete_btn = False
        
        if save_btn:
            # Parse keywords
            keywords = [k.strip() for k in keywords_input.split(',') if k.strip()]
            
            # Build playbook object
            new_playbook = {
                'id': pb_id,
                'name': pb_name,
                'conditions': {
                    'severity': severities,
                    'keywords': keywords
                },
                'steps': st.session_state[f'editing_steps_{form_key}']
            }
            
            # Validate
            valid, error = validate_playbook(new_playbook)
            if not valid:
                st.error(f"Validation error: {error}")
            else:
                # Check for duplicate IDs (only for new playbooks)
                if playbook is None:
                    if any(pb['id'] == pb_id for pb in all_playbooks):
                        st.error(f"A playbook with ID '{pb_id}' already exists.")
                        return
                
                # Save
                if idx is not None:
                    # Update existing
                    all_playbooks[idx] = new_playbook
                else:
                    # Add new
                    all_playbooks.append(new_playbook)
                
                if save_playbooks(all_playbooks):
                    record("playbook_saved", {"id": pb_id, "name": pb_name, "steps": len(new_playbook["steps"])})
                    st.success(f"Playbook '{pb_name}' saved successfully!")
                    st.session_state.creating_new = False
                    st.session_state.selected_playbook_idx = None
                    if f'editing_steps_{form_key}' in st.session_state:
                        del st.session_state[f'editing_steps_{form_key}']
                    st.rerun()
        
        if delete_btn and idx is not None:
            removed = all_playbooks.pop(idx)
            if save_playbooks(all_playbooks):
                record("playbook_deleted", {"id": removed.get("id")})
                st.success("Playbook deleted.")
                st.session_state.selected_playbook_idx = None
                if f'editing_steps_{form_key}' in st.session_state:
                    del st.session_state[f'editing_steps_{form_key}']
                st.rerun()

