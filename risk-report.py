#!/usr/bin/python3.9

# Copyright 2024 University of Southampton IT Innovation Centre

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# <!-- SPDX-License-Identifier: Apache 2.0 -->
# <!-- SPDX-FileCopyrightText: 2024 The University of Southampton IT Innovation Centre -->
# <!-- SPDX-ArtifactOfProjectName: Spyderisk -->
# <!-- SPDX-FileType: Source code -->
# <!-- SPDX-FileComment: Original by Stephen Phillips, May 2024 -->

import argparse
import copy
import csv
import gzip
import logging
import re
import tempfile
import time
from functools import cache, cached_property
from itertools import chain
from pathlib import Path

import boolean
from rdflib import ConjunctiveGraph, Literal, URIRef

VERSION = "1.0"

algebra = boolean.BooleanAlgebra()
TRUE, FALSE, NOT, AND, OR, symbol = algebra.definition()

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

parser = argparse.ArgumentParser(description="Generate risk reports for Spyderisk system models",
                                 epilog="e.g. risk-report.py -i SteelMill.nq.gz -o steel.pdf -d ../domain-network/csv/ -m MS-LossOfControl-f8b49f60")
parser.add_argument("-i", "--input", dest="input", required=True, metavar="input_NQ_filename", help="Filename of the validated system model NQ file (compressed or not)")
parser.add_argument("-o", "--output", dest="output", required=True, metavar="output_csv_filename", help="Output CSV filename")
parser.add_argument("-d", "--domain", dest="csvs", required=True, metavar="CSV_directory", help="Directory containing the domain model CSV files")
parser.add_argument("-m", "--misbehaviour", dest="misbehaviours", required=False, nargs="+", metavar="URI_fragment", help="Target misbehaviour IDs, e.g. 'MS-LossOfControl-f8b49f60'. If not specified then the high impact and high risk ones will be analysed.")
parser.add_argument("-s", "--simple-root-causes", dest="simple_root_causes", action="store_true", help="Keep the root causes simple (no top-level OR). Using this means more repetition.")
parser.add_argument("--hide-initial-causes", dest="hide_initial_causes", action="store_true", help="Don't output the initial causes")
parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)

raw = parser.parse_args()
args = vars(raw)

nq_filename = args["input"]
csv_directory = args["csvs"]
output_filename = args["output"]
target_ms_uris = args["misbehaviours"]

SHOW_LIKELIHOOD_IN_DESCRIPTION = False

domain_misbehaviours_filename = Path(csv_directory) / "Misbehaviour.csv"
domain_trustworthiness_attributes_filename = Path(csv_directory) / "TrustworthinessAttribute.csv"
domain_ca_settings_filename = Path(csv_directory) / "CASetting.csv"
domain_controls_filename = Path(csv_directory) / "Control.csv"
domain_control_strategies_filename = Path(csv_directory) / "ControlStrategy.csv"
domain_trustworthiness_levels_filename = Path(csv_directory) / "TrustworthinessLevel.csv"
domain_likelihood_levels_filename = Path(csv_directory) / "Likelihood.csv"
domain_impact_levels_filename = Path(csv_directory) / "ImpactLevel.csv"
domain_risk_levels_filename = Path(csv_directory) / "RiskLevel.csv"
domain_risk_lookup_filename = Path(csv_directory) / "RiskLookupTable.csv"

# Constants to query RDF:
CORE = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/core"
DOMAIN = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain"
SYSTEM = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/system"

HAS_TYPE = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
HAS_ID = URIRef(CORE + "#hasID")
HAS_COMMENT = URIRef("http://www.w3.org/2000/01/rdf-schema#comment")
HAS_LABEL = URIRef("http://www.w3.org/2000/01/rdf-schema#label")

CAUSES_DIRECT_MISBEHAVIOUR = URIRef(CORE + "#causesDirectMisbehaviour")
CAUSES_INDIRECT_MISBEHAVIOUR = URIRef(CORE + "#causesIndirectMisbehaviour")
HAS_SECONDARY_EFFECT_CONDITION = URIRef(CORE + "#hasSecondaryEffectCondition")
AFFECTS = URIRef(CORE + "#affects")
AFFECTED_BY = URIRef(CORE + "#affectedBy")
HAS_ENTRY_POINT = URIRef(CORE + "#hasEntryPoint")
IS_ROOT_CAUSE = URIRef(CORE + "#isRootCause")
APPLIES_TO = URIRef(CORE + "#appliesTo")
LOCATED_AT = URIRef(CORE + "#locatedAt")
HAS_NODE = URIRef(CORE + "#hasNode")
HAS_ASSET = URIRef(CORE + "#hasAsset")
HAS_MISBEHAVIOUR = URIRef(CORE + "#hasMisbehaviour")
HAS_TWA = URIRef(CORE + "#hasTrustworthinessAttribute")
HAS_INFERRED_LEVEL = URIRef(CORE + "#hasInferredLevel")
HAS_ASSERTED_LEVEL = URIRef(CORE + "#hasAssertedLevel")
THREAT = URIRef(CORE + "#Threat")
HAS_PRIOR = URIRef(CORE + "#hasPrior")
HAS_IMPACT = URIRef(CORE + "#hasImpactLevel")
HAS_RISK = URIRef(CORE + "#hasRisk")
HAS_FREQUENCY = URIRef(CORE + "#hasFrequency")
MISBEHAVIOUR_SET = URIRef(CORE + "#MisbehaviourSet")
MITIGATES = URIRef(CORE + "#mitigates")
BLOCKS = URIRef(CORE + "#blocks")
HAS_CONTROL_SET = URIRef(CORE + "#hasControlSet")
HAS_MANDATORY_CONTROL_SET = URIRef(CORE + "#hasMandatoryCS")
CONTROL_SET = URIRef(CORE + "#ControlSet")
HAS_COVERAGE = URIRef(CORE + "#hasCoverageLevel")
HAS_CONTROL = URIRef(CORE + "#hasControl")
IS_PROPOSED = URIRef(CORE + "#isProposed")
CAUSES_THREAT = URIRef(CORE + "#causesThreat")
CAUSES_MISBEHAVIOUR = URIRef(CORE + "#causesMisbehaviour")
IS_EXTERNAL_CAUSE = URIRef(CORE + "#isExternalCause")
IS_INITIAL_CAUSE = URIRef(CORE + "#isInitialCause")
IS_NORMAL_OP = URIRef(CORE + "#isNormalOp")
IS_NORMAL_OP_EFFECT = URIRef(CORE + "#isNormalOpEffect")
PARENT = URIRef(CORE + "#parent")
CONTROL_STRATEGY = URIRef(CORE + "#ControlStrategy")
TRUSTWORTHINESS_ATTRIBUTE_SET = URIRef(CORE + "#TrustworthinessAttributeSet")
INFINITY = 99999999

# WARNING: Domain model specific predicates
DEFAULT_TW_ATTRIBUTE = URIRef(DOMAIN + "#DefaultTW")
IN_SERVICE = URIRef(DOMAIN + "#InService")

# The second line of a CSV file often contains default values and if so will include domain#000000
DUMMY_URI = "domain#000000"

def load_domain_misbehaviours(filename):
    """Load misbehaviours from the domain model so that we can use the labels"""
    misbehaviour = {}
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        uri_index = header.index("URI")
        label_index = header.index("label")
        comment_index = header.index("comment")
        for row in reader:
            if DUMMY_URI in row: continue
            uri = row[uri_index]
            misbehaviour[uri] = {}
            misbehaviour[uri]["label"] = row[label_index]
            misbehaviour[uri]["description"] = row[comment_index]
    return misbehaviour

def load_domain_trustworthiness_attributes(filename):
    """Load trustworthiness attributes from the domain model so that we can use the labels"""
    ta = {}
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        uri_index = header.index("URI")
        label_index = header.index("label")
        comment_index = header.index("comment")
        for row in reader:
            if DUMMY_URI in row: continue
            uri = row[uri_index]
            ta[uri] = {}
            ta[uri]["label"] = row[label_index]
            ta[uri]["description"] = row[comment_index]
    return ta

def load_domain_controls(filename):
    """Load controls from the domain model so that we can use the labels"""
    control = {}
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        uri_index = header.index("URI")
        label_index = header.index("label")
        for row in reader:
            if DUMMY_URI in row: continue
            uri = row[uri_index]
            control[uri] = {}
            control[uri]["label"] = row[label_index]
    return control

def load_domain_control_strategies(filename):
    """Load control strategies from the domain model so that we can use the labels and current/future attributes"""
    csg = {}
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        uri_index = header.index("URI")
        label_index = header.index("label")
        current_index = header.index("currentRisk")
        future_index = header.index("futureRisk")
        blocking_index = header.index("hasBlockingEffect")
        for row in reader:
            if DUMMY_URI in row: continue
            uri = row[uri_index]
            csg[uri] = {}
            csg[uri]["label"] = row[label_index]
            csg[uri]["currentRisk"] = False if row[current_index] == "FALSE" else True
            csg[uri]["futureRisk"] = False if row[future_index] == "FALSE" else True
            csg[uri]["hasBlockingEffect"] = row[blocking_index]
    return csg

def load_domain_ca_settings(filename):
    """Load information from the domain model so that we know which control sets are assertable"""
    settings = {}
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        uri_index = header.index("URI")
        assertable_index = header.index("isAssertable")
        for row in reader:
            if DUMMY_URI in row: continue
            assertable = True if row[assertable_index] == "TRUE" else False
            settings[row[uri_index].split('#')[1]] = assertable
    return settings

def load_domain_levels(filename):
    """Load levels from the domain model (works for impact, risk, trustworthiness and likelihood)"""
    tw = {}
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        uri_index = header.index("URI")
        level_index = header.index("levelValue")
        label_index = header.index("label")
        for row in reader:
            if DUMMY_URI in row: continue
            uri = row[uri_index]
            tw[uri] = {}
            tw[uri]["number"] = int(row[level_index])
            tw[uri]["label"] = row[label_index]
    return tw

def load_risk_lookup(filename):
    """Load the risk lookup matrix"""
    risk = {}
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        iv_index = header.index("IV")
        lv_index = header.index("LV")
        rv_index = header.index("RV")
        for row in reader:
            if DUMMY_URI in row: continue
            iv = int(row[iv_index])
            lv = int(row[lv_index])
            rv = int(row[rv_index])
            if iv not in risk:
                risk[iv] = { lv: rv }
            else:
                risk[iv][lv] = rv
    return risk

def un_camel_case(text):
    text = text.strip()
    if text == "": return "****"
    text = text.replace("TW", "Trustworthiness")
    if text[0] == "[":
        return text
    else:
        text = re.sub('([a-z])([A-Z])', r'\1 \2', text)
        text = text.replace("Auth N", "AuthN")  # re-join "AuthN" into one word
        text = re.sub('(AuthN)([A-Z])', r'\1 \2', text)
        text = text.replace("Io T", "IoT")  # re-join "IoT" into one word
        text = re.sub('(IoT)([A-Z])', r'\1 \2', text)
        text = re.sub('([A-Z]{2,})([A-Z][a-z])', r'\1 \2', text)  # split out e.g. "PIN" or "ID" as a separate word
        text = text.replace('BIO S', 'BIOS ')  # one label is "BIOSatHost"
        return text

def abbreviate_asset_label(label):
    if label.startswith("[ClientServiceChannel:"):
        # Example input:
        # [ClientServiceChannel:(Philip's PC)-(Philip's Web Browser)-(Web Server)-Website-[NetworkPath:Internet-[NetworkPath:(Shop DMZ)]]]
        bits = label.split("-")
        return "[ClientServiceChannel:" + bits[1] + "-" + bits[3]
    return label

def make_symbol(uriref):
    """Make a symbol from the URIRef for use in logical expressions"""
    return symbol(uriref.split('#')[1])

def get_comment_from_match(frag_match):
    """Converts from e.g. Symbol('MS-LossOfControl-f8b49f60') to the entity's comment"""
    # TODO: this references a global variable, which is not ideal
    return system_model.get_entity(URIRef(SYSTEM + "#" + frag_match.group()[8:-2])).short_comment

class LogicalExpression():
    """Represents a Boolean expression using URI fragments as the symbols."""
    def __init__(self, cause_list, all_required=True):
        """Arguments:

        cause_list: list
                can be a mixture of None, LogicalExpression and symbol
        all_required: Boolean
                whether all the parts of the expression are required (resulting in an AND) or not (giving an OR)
        """
        all_causes = []
        for cause in cause_list:
            if isinstance(cause, LogicalExpression):
                all_causes.append(cause.cause)
            else:
                all_causes.append(cause)

        all_causes = [c for c in all_causes if c is not None]

        if len(all_causes) == 0:
            self.cause = None
        elif len(all_causes) == 1:
            self.cause = all_causes[0]
        else:
            if all_required:
                self.cause = AND(*all_causes).simplify()
            else:
                self.cause = OR(*all_causes).simplify()

    @classmethod
    def create_or_none(cls, cause_list, all_required=True):
        """Factory method to create a LogicalExpression or return None if the cause_list is empty after filtering out None values"""
        cause_list = [cause for cause in cause_list if cause is not None]
        if len(cause_list) == 0:
            return None
        return cls(cause_list, all_required)

    def __str__(self):
        """Single line representation with the URIs replaced with the entity comment"""
        if self.cause is None:
            return "-None-"
        cause = algebra.dnf(self.cause.simplify())
        symb = re.compile(r'Symbol\(\'.*?\'\)')
        return symb.sub(get_comment_from_match, repr(cause))

    def __eq__(self, other):
        if hasattr(other, 'cause'):
            return self.cause == other.cause
        else:
            return False

    def __hash__(self) -> int:
        return hash(self.cause)

    @property
    def uris(self):
        return set([URIRef(SYSTEM + "#" + str(symbol)) for symbol in self.cause.get_symbols()])

    @property
    def complexity(self):
        return str(self.cause.args).count("Symbol")

    def pretty_print(self, max_complexity=500):
        if self.cause is None:
            return "None"
        if self.complexity <= max_complexity:
            cause = algebra.dnf(self.cause.simplify())
            symb = re.compile(r'Symbol\(\'.*?\'\)')
            cause = symb.sub(get_comment_from_match, cause.pretty())
        else:
            cause = "Complexity: " + str(self.complexity)
        return cause

    @property
    def dnf_terms(self):
        """Return the terms of the DNF form of the expression as a list."""
        if self.cause is None:
            return []
        dnf = algebra.dnf(self.cause.simplify())
        # if dnf form is just 1 symbol or the operator is AND then just return it, otherwise it is an OR and we need to return its terms (args)
        if len(dnf.symbols) == 1 or dnf.operator == "AND":
            return [dnf]
        else:
            return dnf.args
    
class LoopbackError(Exception):
    """Exception raised when attempting to visit a parent node (cause) that is also a child (effect) during tree traversal."""
    def __init__(self, loopback_node_uris: set = None) -> None:
        """
        Initialize the LoopbackError exception.

        Args:
            loopback_node_uris (set): Set of URIs of nodes causing the loopback (non-empty).
        """
        if loopback_node_uris is None:
            # TODO: following line is never used. Should probably throw an exception and also check that set is not empty
            loopback_node_uris = set()
        self.loopback_node_uris = loopback_node_uris

    def __str__(self) -> str:
        return f"Error encountered during tree traversal. Loopback nodes: {self.loopback_node_uris}"

# TODO: Add the domain model as a parameter? And load domain model from NQ rather than CSV files
class Graph(ConjunctiveGraph):
    """Represents the system model as an RDF graph."""
    def __init__(self, nq_filename):
        super().__init__()
        if nq_filename.endswith(".gz"):
            with gzip.open(nq_filename, "rb") as f:
                self.parse(f, format="nquads")
        else:
            self.parse(nq_filename, format="nquads")

    def get_entity(self, uriref):
        if (uriref, HAS_TYPE, MISBEHAVIOUR_SET) in self:
            return MisbehaviourSet(uriref, self)
        elif (uriref, HAS_TYPE, THREAT) in self:
            return Threat(uriref, self)
        elif (uriref, HAS_TYPE, CONTROL_STRATEGY) in self:
            return ControlStrategy(uriref, self)
        elif (uriref, HAS_TYPE, TRUSTWORTHINESS_ATTRIBUTE_SET) in self:
            return TrustworthinessAttributeSet(uriref, self)
        else:
            raise KeyError(uriref)

    @cache
    def threat(self, uriref):
        return Threat(uriref, self)

    @cache
    def misbehaviour(self, uriref):
        return MisbehaviourSet(uriref, self)

    @cache
    def control_strategy(self, uriref):
        return ControlStrategy(uriref, self)

    @cache
    def trustworthiness_attribute_set(self, uriref):
        return TrustworthinessAttributeSet(uriref, self)

    @property
    def threats(self):
        return [self.threat(uriref) for uriref in self.subjects(HAS_TYPE, THREAT)]

    @property
    def misbehaviours(self):
        return [self.misbehaviour(uriref) for uriref in self.subjects(HAS_TYPE, MISBEHAVIOUR_SET)]

    @property
    def control_strategies(self):
        return [self.control_strategy(uriref) for uriref in self.subjects(HAS_TYPE, CONTROL_STRATEGY)]

    @property
    def trustworthiness_attribute_sets(self):
        return [self.trustworthiness_attribute_set(uriref) for uriref in self.subjects(HAS_TYPE, TRUSTWORTHINESS_ATTRIBUTE_SET)]

    def label(self, uriref):
        return self.value(subject=uriref, predicate=HAS_LABEL)


# TODO: consider making this extend URIRef as this might provide useful identity value. We could then use the Entity subclasses in the current_path for instance
class Entity():
    """Superclass of Threat, Misbehaviour, Trustwworthiness Attribute or Control Strategy."""
    def __init__(self, uriref, graph):
        self.uriref = uriref
        self.graph = graph
    
    def __hash__(self):
        return hash(self.uriref)

    def __eq__(self, other):
        if not isinstance(other, Entity):
            return False
        return (self.uriref == other.uriref)

class ControlStrategy(Entity):
    """Represents a Control Strategy."""
    def __init__(self, uriref, graph):
        super().__init__(uriref, graph)

    def __str__(self):
        return "Control Strategy: {} ({}) / Effectiveness: {} / Max Likelihood: {}".format(
            self.description, str(self.uriref), str(self.effectiveness_number), str(self.maximum_likelihood))

    @property
    def description(self):
        asset_labels = self.control_set_asset_labels()  # get unique set of asset labels the CSG involves (whether proposed or not)
        asset_labels = [f'"{abbreviate_asset_label(label)}"' for label in asset_labels]
        asset_labels.sort()
        comment = "{} ({})".format(un_camel_case(dm_control_strategies[self._domain_model_uri()]["label"]), ", ".join(asset_labels))
        return comment

    def _domain_model_uri(self):
        return self.graph.value(self.uriref, PARENT).split("/")[-1]

    def _effectiveness_uri(self):
        return dm_control_strategies[self._domain_model_uri()]["hasBlockingEffect"].split("/")[-1]

    @property
    def effectiveness_number(self):
        return dm_trustworthiness_levels[self._effectiveness_uri()]["number"]

    @property
    def effectiveness_label(self):
        return dm_trustworthiness_levels[self._effectiveness_uri()]["label"]

    @property
    def maximum_likelihood(self):
        """Return the maximum likelihood of the Threats that this Control Strategy can block.
        
        Simply, this is the inverse of the CSG's effectiveness. However, we also need to take into account the coverage levels of the mandatory control sets.
        The maximum likelihood is the minimum of the CSG's effectiveness and the minimum coverage of the mandatory control sets.
        We do not check here whether the CSG or CS are active or not, as we want to know the maximum potential effectiveness.
        """
        control_sets = self.graph.objects(self.uriref, HAS_MANDATORY_CONTROL_SET)
        min_coverage = INFINITY
        for cs in control_sets:
            coverage_uri_fragment = self.graph.value(cs, HAS_COVERAGE).split("/")[-1]
            coverage_level = dm_trustworthiness_levels[coverage_uri_fragment]["number"]
            min_coverage = min(min_coverage, coverage_level)
        return inverse(min(self.effectiveness_number, min_coverage))

    @property
    def is_current_risk_csg(self):
        parent_uriref = self._domain_model_uri()
        return dm_control_strategies[parent_uriref]["currentRisk"] and ("-Runtime" in str(parent_uriref) or "-Implementation" in str(parent_uriref))

    @property
    def is_future_risk_csg(self):
        return dm_control_strategies[self._domain_model_uri()]["futureRisk"]

    @cached_property
    def blocked_threats(self):
        return [self.graph.threat(threat_uriref) for threat_uriref in self.graph.value(self.uriref, BLOCKS)]

    @property
    def is_active(self):
        # TODO: do we need to check sufficient CS?
        # TODO: make a CS class?
        control_sets = self.graph.objects(self.uriref, HAS_MANDATORY_CONTROL_SET)
        all_proposed = True
        for cs in control_sets:
            if (cs, IS_PROPOSED, Literal(True)) not in self.graph:
                all_proposed = False
        return all_proposed

    def control_set_urirefs(self):
        return self.graph.objects(self.uriref, HAS_MANDATORY_CONTROL_SET)

    def control_set_asset_urirefs(self):
        cs_urirefs = self.control_set_urirefs()
        asset_urirefs = []
        for cs_uriref in cs_urirefs:
            asset_urirefs += self.graph.objects(cs_uriref, LOCATED_AT)
        return asset_urirefs

    def control_set_asset_labels(self):
        return sorted(list(set([self.graph.label(asset_uriref) for asset_uriref in self.control_set_asset_urirefs()])))

class TrustworthinessAttributeSet(Entity):
    """Represents a Trustworthiness Attribute Set."""
    def __init__(self, uriref, graph):
        super().__init__(uriref, graph)

    def __str__(self):
        return "Trustworthiness Attribute Set: {}\n  Label: {}\n  Description: {}\n".format(
            str(self.uriref), self.label, self.description)

    def _twa_uri(self):
        return self.graph.value(self.uriref, HAS_TWA).split('/')[-1]

    def _asserted_tw_level_uri(self):
        uriref = self.graph.value(self.uriref, HAS_ASSERTED_LEVEL)
        if uriref is None:
            return None
        return uriref.split('/')[-1]

    def _inferred_tw_level_uri(self):
        uriref = self.graph.value(self.uriref, HAS_INFERRED_LEVEL)
        if uriref is None:
            return None
        return uriref.split('/')[-1]

    @property
    def label(self):
        """Return a TWAS label"""
        try:
            return dm_trustworthiness_attributes[self._twa_uri()]["label"]
        except KeyError:
            # might get here if the domain model CSVs are the wrong ones
            logging.warning("No TWAS label for " + str(self.uriref))
            return "**TWAS label**"

    @property
    def comment(self):
        """Return a short description of a TWAS"""
        tw_level = self.inferred_level_label
        twa = self.label
        asset_uriref = self.graph.value(subject=self.uriref, predicate=LOCATED_AT)
        asset = self.graph.label(asset_uriref)
        return '{} of {} is {}'.format(un_camel_case(twa), asset, tw_level)

    @property
    def description(self):
        """Return a long description of a TWAS"""
        try:
            return dm_trustworthiness_attributes[self._twa_uri()]["description"]
        except KeyError:
            # might get here if the domain model CSVs are the wrong ones
            logging.warning("No TWAS description for " + str(self.uriref))
            return "**TWAS description**"

    @property
    def inferred_level_number(self):
        return dm_trustworthiness_levels[self._inferred_tw_level_uri()]["number"]

    @property
    def inferred_level_label(self):
        return dm_trustworthiness_levels[self._inferred_tw_level_uri()]["label"]

    @property
    def asserted_level_number(self):
        return dm_trustworthiness_levels[self._asserted_tw_level_uri()]["number"]

    @property
    def inferred_level_label(self):
        return dm_trustworthiness_levels[self._asserted_tw_level_uri()]["label"]

    @property
    def is_external_cause(self):
        return (self.uriref, IS_EXTERNAL_CAUSE, Literal(True)) in self.graph

    # TODO: this uses a domain-specific predicate. Don't incorporate it into a general class
    @property
    def is_default_tw(self):
        """Return Boolean describing whether this is a TWAS which has the Default TW attribute"""
        return (self.uriref, HAS_TWA, DEFAULT_TW_ATTRIBUTE) in self.graph

class Threat(Entity):
    """Represents a Threat."""
    def __init__(self, uri_ref, graph):
        super().__init__(uri_ref, graph)
        self.cached_explanations = []

    def __str__(self):
        return "Threat: {} ({})".format(self.short_comment, str(self.uriref))

    def _likelihood_uri(self):
        uriref = self.graph.value(self.uriref, HAS_PRIOR)
        if uriref is None:
            return None
        return uriref.split('/')[-1]

    def _risk_uri(self):
        uriref = self.graph.value(self.uriref, HAS_RISK)
        if uriref is None:
            return None
        return uriref.split('/')[-1]

    def _frequency_uri(self):
        uriref = self.graph.value(self.uriref, HAS_FREQUENCY)
        if uriref is None:
            return None
        return uriref.split('/')[-1]

    def _short_comment(self):
        """Return the first part of the threat description (up to the colon)"""
        comment = self.graph.value(subject=self.uriref, predicate=HAS_COMMENT)
        quote_counter = 0
        char_index = 0
        # need to deal with the case where there is a colon in a quoted asset label
        while (comment[char_index] != ":" or quote_counter % 2 != 0):
            if comment[char_index] == '"':
                quote_counter += 1
            char_index += 1
        comment = comment[0:char_index]
        return comment

    @property
    def short_comment(self):
        """Return the first part of the threat description (up to the colon) and add in the likelihood if so configured"""
        comment = self._short_comment()
        comment = comment.replace('re-disabled at "Router"', 're-enabled at "Router"')  # hack that is necessary to correct an error in v6a3-1-4 for the overview paper system model
        if not SHOW_LIKELIHOOD_IN_DESCRIPTION:
            return comment
        else:
            return '{} likelihood of: {}'.format(self.likelihood_label, comment)

    @property
    def comment(self):
        """Return the full threat description"""
        return self.graph.value(subject=self.uriref, predicate=HAS_COMMENT)

    @property
    def description(self):
        """Return the longer description of a threat (after the colon)"""
        short_comment = self._short_comment()
        comment = self.graph.value(subject=self.uriref, predicate=HAS_COMMENT)
        comment = comment[len(short_comment) + 1:]  # remove the short comment from the start
        comment = comment.lstrip()  # there is conventionally a space after the colon
        char = comment[0]
        return char.upper() + comment[1:]  # uppercase the first word

    @property
    def likelihood_number(self):
        if self._likelihood_uri() is None:
            return -1
        return dm_likelihood_levels[self._likelihood_uri()]["number"]

    @property
    def likelihood_label(self):
        if self._likelihood_uri() is None:
            return "N/A"
        return dm_likelihood_levels[self._likelihood_uri()]["label"]

    @property
    def risk_number(self):
        if self._risk_uri() is None:
            return -1
        return dm_risk_levels[self._risk_uri()]["number"]

    @property
    def risk_label(self):
        if self._risk_uri() is None:
            return "N/A"
        return dm_risk_levels[self._risk_uri()]["label"]

    @property
    def frequency_number(self):
        if self._frequency_uri() is None:
            return None
        return dm_likelihood_levels[self._frequency_uri()]["number"]

    @property
    def frequency_label(self):
        if self._frequency_uri() is None:
            return None
        return dm_likelihood_levels[self._frequency_uri()]["label"]

    @property
    def is_normal_op(self):
        return (self.uriref, IS_NORMAL_OP, Literal(True)) in self.graph

    @property
    def is_root_cause(self):
        return (self.uriref, IS_ROOT_CAUSE, Literal(True)) in self.graph

    @property
    def is_secondary_threat(self):
        return (self.uriref, HAS_SECONDARY_EFFECT_CONDITION, None) in self.graph

    @property
    def is_primary_threat(self):
        return (self.uriref, HAS_ENTRY_POINT, None) in self.graph

    @property
    def is_initial_cause(self):
        """Return Boolean describing if the Threat is an 'initial cause'"""
        return (self.uriref, IS_INITIAL_CAUSE, Literal(True)) in self.graph

    @property
    def trustworthiness_attribute_sets(self):
        return [self.graph.trustworthiness_attribute_set(uriref) for uriref in self.graph.objects(self.uriref, HAS_ENTRY_POINT)]

    @property
    def primary_threat_misbehaviour_parents(self):
        """Get all the Misbehaviours that can cause this Threat (disregarding likelihoods), for primary Threat types"""
        ms_urirefs = []
        entry_points = self.graph.objects(self.uriref, HAS_ENTRY_POINT)
        for twas in entry_points:
            twis = self.graph.value(predicate=AFFECTS, object=twas)
            ms_urirefs.append(self.graph.value(twis, AFFECTED_BY))
        return [self.graph.misbehaviour(ms_uriref) for ms_uriref in ms_urirefs]

    @property
    def primary_threat_twas_ms(self):
        """Get all the (TWAS, MisbehaviourSets) that can cause this Threat (disregarding likelihoods), for primary Threat types"""
        twas_ms = []
        entry_points = self.graph.objects(self.uriref, HAS_ENTRY_POINT)
        for twas_uriref in entry_points:
            twas = self.graph.trustworthiness_attribute_set(twas_uriref)
            twis = self.graph.value(predicate=AFFECTS, object=twas_uriref)
            ms = self.graph.misbehaviour(self.graph.value(twis, AFFECTED_BY))
            twas_ms.append((twas, ms))
        return twas_ms

    @property
    def secondary_threat_misbehaviour_parents(self):
        """Get all the Misbehaviours that can cause this Threat (disregarding likelihoods), for secondary Threat types"""
        ms_urirefs = self.graph.objects(self.uriref, HAS_SECONDARY_EFFECT_CONDITION)
        return [self.graph.misbehaviour(ms_uriref) for ms_uriref in ms_urirefs]

    @property
    def misbehaviour_parents(self):
        """Get all the Misbehaviours that can cause this Threat (disregarding likelihoods), for all Threat types"""
        return self.primary_threat_misbehaviour_parents + self.secondary_threat_misbehaviour_parents

    @property
    def twas_ms_parents(self):
        """Get all the (TWAS, MisbehaviourSets) that can cause this Threat (disregarding likelihoods), for all Threat types. For secondary Threats, the TWAS is None."""
        p = self.primary_threat_twas_ms
        s = self.secondary_threat_misbehaviour_parents
        for ms in s:
            p.append((None, ms))
        return p

    @property
    def control_strategies(self, future_risk=True):
        """Return list of control strategy objects that block the threat"""
        csgs = []
        # the "blocks" predicate means a CSG appropriate for current or future risk calc
        # the "mitigates" predicate means a CSG appropriate for future risk (often a contingency plan for a current risk CSG); excluded from likelihood calc in current risk
        # The "mitigates" predicate is not used in newer domain models
        if future_risk:
            for csg_uri in chain(self.graph.subjects(BLOCKS, self.uriref), self.graph.subjects(MITIGATES, self.uriref)):
                csg = self.graph.control_strategy(csg_uri)
                if csg.is_future_risk_csg:
                    csgs.append(csg)
        else:
            for csg_uri in self.graph.subjects(BLOCKS, self.uriref):
                csg = self.graph.control_strategy(csg_uri)
                if csg.is_current_risk_csg and not csg.has_inactive_contingency_plan:
                    csgs.append(csg)
        return csgs

    def is_root_cause_disregarding_likelihood(self, is_normal_effect):
        """Return whether the Threat is a root cause, disregarding the likelihood from the risk calculation.
        
        A root cause from the risk calculation is defined as a threat which:
        - is not a normal operation (it is an “offensive” threat);
        - has a non-negligible likelihood (it will cause something else);
        - all its entry points:
            - are external causes (TWAS) or
            - are normal operation effects (Misbehaviours in the normal operation graph).

        Here we check everything apart from the non-negligible likelihood condition.
        """
        if self.is_normal_op:
            # logging.debug(f"Threat {self.uriref} is normal operation")
            return False
        for twas, ms in self.twas_ms_parents:
            if twas is not None:
                # Then it was a TWAS/MS pair (as in primary threat)
                if not twas.is_external_cause and not is_normal_effect[ms.uriref]:
                    # logging.debug(f"Threat {self.uriref} has a non-external TWAS {twas.uriref} and non-normal operation Misbehaviour {ms.uriref}")
                    return False
            else:
                # Then it was an MS only (as in secondary threat)
                if not ms.is_normal_op:
                    # logging.debug(f"Threat {self.uriref} has a non-normal operation Misbehaviour {ms.uriref}")
                    return False
        return True

    @property
    def local_uncontrolled_likelihood(self):
        """The likelihood of the threat disregarding any active control strategies at the threat."""

        # For a primary threat it's the entry-point TWASs' inferred values we need to look at.
        #     The inferred TWAS levels will have taken into account the asserted levels and the inferred likelihoods of the causing misbehaviours.
        # For a secondary threat it's the minimum likelihood of the causal misbehaviours (secondary effect conditions).
        # We need to take into account that threats can have mixed causes (so can be both "primary" and "secondary"). The minimum likelihood of these causes is used.

        inferred_twas_trustworthiness_levels = [twas.inferred_level_number for twas in self.trustworthiness_attribute_sets]
        inferred_twas_likelihoods = [inverse(level) for level in inferred_twas_trustworthiness_levels]
        if len(inferred_twas_likelihoods) > 0:
            inferred_twas_likelihood = min(inferred_twas_likelihoods)  # take min() as this is a threat
        else:
            inferred_twas_likelihood = float('inf')  # Larger than the top of the actual scale

        secondary_parent_misbehaviour_likelihoods = [ms.likelihood_number for ms in self.secondary_threat_misbehaviour_parents]
        if len(secondary_parent_misbehaviour_likelihoods) > 0:
            secondary_parent_misbehaviour_likelihood = min(secondary_parent_misbehaviour_likelihoods)  # take min() as this is a threat
        else:
            secondary_parent_misbehaviour_likelihood = float('inf')

        likelihood = min(inferred_twas_likelihood, secondary_parent_misbehaviour_likelihood)  # take min() as all causes are needed

        # A threat's likelihood cannot go above its frequency, if it is defined
        if self.frequency_number is not None:
            likelihood = min(likelihood, self.frequency_number)

        return likelihood

    def explain_likelihood(self, current_path=None):
        """Return an explanation of the likelihood of the Threat, given the path taken to get to the Threat. Return a cached result if there is a valid one."""
        if current_path is None:
            current_path = ()

        normal_op = " (normal operation)" if self.is_normal_op else ""
        logging.debug("    " * len(current_path) + "Explaining Threat: " + str(self.uriref) + " (" + self.short_comment + ")" + normal_op)

        # See MisbehaviourSet.explain_likelihood for explanation of cache validity
        for index, explanation in enumerate(self.cached_explanations):
            if len(explanation.loopback_node_uris.intersection(current_path)) == len(explanation.loopback_node_uris) and len(explanation.cause_node_uris.intersection(current_path)) == 0:
                logging.debug("    " * (len(current_path) + 1) + f"Reusing cached explanation {index}: {explanation}")
                return explanation

        # If there was nothing in the cache we can use, do the calculation and save the result before returning it
        explanation = self._explain_likelihood(current_path)
        logging.debug("    " * (len(current_path) + 1) + f"New explanation {len(self.cached_explanations)}: {explanation}")
        self.cached_explanations.append(explanation)
        return explanation

    def _explain_likelihood(self, current_path):
        """Return an explanation of the likelihood of the Threat, given the path taken to get to the Threat."""

        # General strategy:
        #   Examine all parent Misbehaviours (of both primary and secondary Threats) that are not already in the current path
        #   Put the returned tuples in parent_explanations
        #   A Threat requires all of its causes to be on good paths

        # Combine and return parent explanations:
        #     AND(initial_cause expressions) or self if self is initial_cause
        #     AND(root_cause expressions) or self if self is root_cause
        #     min(upstream_uncontrolled_likelihood values) combined with the uncontrolled_inferred_likelihood
        #     union(all cause_node_uris)
        #       also adding self to the set
        #     union(loopback_node_uris)
        #       also removing self from the set to ensure the return value describes just the tree starting at self
        #     union(csg_reports)
        #       also adding any at self
        #     AND(uncontrolled_initial_cause expressions) - though there are complications
        #     AND(uncontrolled_root_cause expressions) - though there are complications

        # make a copy of current_path, add self
        current_path = set(current_path)
        current_path.add(self.uriref)

        parent_explanations = []
        twas_ms_parents = self.twas_ms_parents

        is_normal_effect = {}

        if len(twas_ms_parents) == 0:
            # this shouldn't happen
            raise Exception("Threat has no parents")

        # We only need one error to know we should throw an exception, but examining all paths will find all loopback nodes and may make the cached result more useful.
        # TODO: need to check if that is the right strategy, or whether aborting as soon as there is an error is better

        combined_loopback_node_uris = set()
        throw_error = False
        for (twas, ms) in twas_ms_parents:
            if ms.uriref not in current_path:
                try:
                    parent_explanation = ms.explain_likelihood(current_path)  # may throw an exception
                    parent_explanations.append(parent_explanation)
                    is_normal_effect[ms.uriref] = parent_explanation.is_normal_effect  # store this so we can easily use this when working out of the threat is a root cause
                    if twas is not None:
                        # We've jumped from the threat to a misbehaviour parent, bypassing the TWAS which is inbetween.

                        # Save the initial value so we can debug log if it changes
                        initial_upstream = parent_explanation.upstream_uncontrolled_likelihood

                        # A TWAS which is an external cause is normally at the top of the tree but it can be in the middle in some cases.
                        # We want to have the uncontrolled upstream likelihood of a threat to be defined by the first external cause met when moving upstream on any path.

                        # A common case at the top of the tree is when a threat has "NetworkUserTW of Internet" has a TWAS which is asserted to be level 0 (implying level 5 likelihood),
                        # the causing MS is "Internet loses Network User Trustworthiness" and that has max likelihood 0.

                        if twas.is_external_cause:
                            parent_explanation.upstream_uncontrolled_likelihood = inverse(twas.asserted_level_number)
                            if initial_upstream != parent_explanation.upstream_uncontrolled_likelihood:
                                logging.debug("    " * len(current_path) + "Parent TWAS is_external_cause: changing upstream uncontrolled likelihood from " + str(initial_upstream) + " to " + str(parent_explanation.upstream_uncontrolled_likelihood))

                        else:
                            # Potentially increase the upstream_uncontrolled_likelihood if the TWAS is not an external cause and the asserted trustworthiness level is low.
                            twas_ms_likelihood = max(initial_upstream, inverse(twas.asserted_level_number))
                            if twas_ms_likelihood != initial_upstream:
                                parent_explanation.upstream_uncontrolled_likelihood = twas_ms_likelihood
                                logging.debug("    " * len(current_path) + "Parent TWAS has low asserted TW: increasing upstream uncontrolled likelihood from " + str(initial_upstream) + " to " + str(twas_ms_likelihood))
                except LoopbackError as error:
                    logging.debug("    " * len(current_path) + "Error: parent Misbehaviour cannot be caused: " + str(ms.uriref))
                    combined_loopback_node_uris |= error.loopback_node_uris
                    throw_error = True
            else:
                logging.debug("    " * len(current_path) + "Error: parent Misbehaviour is on current path: " + str(ms.uriref))
                combined_loopback_node_uris.add(ms.uriref)
                throw_error = True

        combined_loopback_node_uris.discard(self.uriref)

        if throw_error:
            logging.debug("    " * len(current_path) + "Error: path is not viable")
            raise LoopbackError(combined_loopback_node_uris)

        logging.debug("    " * len(current_path) + "Parent upstream uncontrolled likelihoods: " + str([ret.upstream_uncontrolled_likelihood for ret in parent_explanations]))

        combined_cause_node_uris = set().union(*[ret.cause_node_uris for ret in parent_explanations])
        combined_cause_node_uris.add(self.uriref)

        combined_upstream_uncontrolled_likelihood = min([ret.upstream_uncontrolled_likelihood for ret in parent_explanations])  # take min() as this is a threat

        combined_csg_reports = set().union(*[ret.csg_reports for ret in parent_explanations])

        # If the maximum likelihood this could ever be is zero then just abort as it cannot be a "cause" of anything: we don't care about CSGs at this Threat and it cannot be an uncontrolled cause
        if combined_upstream_uncontrolled_likelihood == 0:
            logging.debug("    " * len(current_path) + "Threat has zero max likelihood so cannot be the cause of anything")
            logging.debug("    " * len(current_path) + "Discarding " + str(len(combined_csg_reports)) + " CSG reports")
            for csg_report in combined_csg_reports:
                logging.debug("    " * len(current_path) + " - " + str(csg_report))
            return Explanation(
                initial_cause=None,
                root_cause=None,
                upstream_uncontrolled_likelihood=0,
                local_uncontrolled_likelihood=self.local_uncontrolled_likelihood,
                cause_node_uris=combined_cause_node_uris,
                loopback_node_uris=combined_loopback_node_uris,
                csg_reports=set(),
                uncontrolled_initial_cause=None,
                uncontrolled_root_cause=None,
                is_normal_effect=False
            )

        # We need a different root cause definition to the meaning of the predicate added in the risk calculation
        # TODO: include secondary threats as well?

        # The "root cause" predicate means:
        #  - not a normal operation (it is an "offensive" threat)
        #  - has a non-zero likelihood
        #  - all it's entry points (parents) are "external causes" (TWAS) or normal operation effects (MisbehaviourSets in the normal operation graph)
        # We can't use this predicate because it is dependent on the likelihood calculation which includes all the control strategies (CSGs) and we need to consider the absence of some CSGs.
        # If we take away CSGs in the normal operation graph then some Threats may gain a non-zero likelihood and so become (additional) root causes.
        # In particular, an offensive threat might be a root cause and have a CSG available. If the CSG has been applied and it is fully effective then the threat will no longer
        # be marked as a root cause by the system-modeller risk calculation.

        # Whether a MisbehaviourSet is a normal effect or not depends on the likelihood calculation (if it has negligible likelihood then it cannot be a normal effect).
        # When computing if a Threat is a root cause we therefore need to pass in whether each parent MisbehaviourSet is a normal effect (disregarding likelihood) or not.
        # We do that with the is_normal_effect dictionary populated above from the parent Explanations.

        is_extra_root_cause = self.is_root_cause_disregarding_likelihood(is_normal_effect) and combined_upstream_uncontrolled_likelihood > 0
        official_is_root_cause = self.is_root_cause  # as calculated by the system-modeller risk calculation
        if is_extra_root_cause != official_is_root_cause:
            logging.warning("    " * len(current_path) + "This threat is also a root cause when the likelihood is disregarded")
        is_root_cause = is_extra_root_cause or official_is_root_cause  # consider all root causes

        if is_root_cause:
            logging.debug("    " * len(current_path) + "Threat is root cause")
            combined_root_cause = LogicalExpression([make_symbol(self.uriref)])
            # Note this (by design) disregards any upstream root causes
        else:
            combined_root_cause = LogicalExpression.create_or_none([ret.root_cause for ret in parent_explanations], all_required=True)

        # TODO: include secondary threats as well? Probably aren't any though?

        if self.is_initial_cause:
            logging.debug("    " * len(current_path) + "Threat is initial cause")
            combined_initial_cause = LogicalExpression([make_symbol(self.uriref)])
            # Note this (by design) disregards any upstream external/initial causes.
        else:
            combined_initial_cause = LogicalExpression.create_or_none([ret.initial_cause for ret in parent_explanations], all_required=True)

        csg_reports = set()
        if len(self.control_strategies) > 0:
            logging.debug("    " * len(current_path) + "Threat has " + str(len(self.control_strategies)) + " Control Strategies. Local uncontrolled likelihood: " + str(self.local_uncontrolled_likelihood) + " / Threat likelihood: " + str(self.likelihood_number))
            for csg in self.control_strategies:
                if combined_upstream_uncontrolled_likelihood > csg.maximum_likelihood and csg.is_active:
                    logging.debug("    " * len(current_path) + "Candidate Control Strategy: " + csg.description + " / Max likelihood: " + str(csg.maximum_likelihood))
                    csg_report = ControlStrategyReport(
                        control_strategy=csg,
                        upstream_uncontrolled_likelihood=combined_upstream_uncontrolled_likelihood,
                        local_uncontrolled_likelihood=self.local_uncontrolled_likelihood,
                        initial_cause=combined_initial_cause,
                        root_cause=combined_root_cause,
                        intermediate_cause=self
                    )
                    csg_reports.add(csg_report)
                    logging.debug("    " * len(current_path) + str(csg_report))

        # If there are no effective CSGs at this Threat then we might have an uncontrolled root cause.
        # See if all the causes are also uncontrolled (have no CSG reports). If so then combine them with an AND.
        # Exclude CSG Reports on normal-op Threats as they don't count for an uncontrolled root cause (they are further up the graph).

        # We actually need to look for uncontrolled trees, including any initial causes or threats in the normal-op graph.
        # Also need to ignore things that are not caused (0 likelihood, i.e. the inherent likelihood is zero, not because it was controlled). That's handled by returning early above when combined_upstream_uncontrolled_likelihood == 0

        combined_uncontrolled_initial_cause = LogicalExpression.create_or_none([parent.uncontrolled_initial_cause for parent in parent_explanations], all_required=True)
        combined_uncontrolled_root_cause = LogicalExpression.create_or_none([parent.uncontrolled_root_cause for parent in parent_explanations], all_required=True)

        if len(csg_reports) > 0:
            # Special case: there are effective CSGs at self
            combined_uncontrolled_initial_cause = None
            combined_uncontrolled_root_cause = None
            logging.debug("    " * len(current_path) + "Threat has an effective CSG => no uncontrolled cause")
        else:
            # Normal case: there are no effective CSGs at self
            # For each parent, it is uncontrolled if the initial_cause or root_cause is uncontrolled (they are both facets of the same thing).
            # A parent is controlled therefore if both the initial_cause and root_cause are controlled, i.e. both None.
            # If any parent is controlled then this Threat is controlled.
            controlled = False
            for parent_explanation in parent_explanations:
                # If a parent is a Misbehaviour at the top of the tree then uncontrolled_initial_cause is None, but it *is* uncontrolled really, we just don't want to add the Misbehaviour to the uncontrolled_initial_cause expression
                # Therefore check that len(parent_cause_node_uris) is greater than 1
                if parent_explanation.uncontrolled_initial_cause is None and parent_explanation.uncontrolled_root_cause is None and len(parent_explanation.cause_node_uris) > 1:
                    controlled = True
                    break
            if controlled:
                logging.debug("    " * len(current_path) + "Threat has 1 or more controlled parents => no uncontrolled cause")
                combined_uncontrolled_initial_cause = None
                combined_uncontrolled_root_cause = None

            if self.is_initial_cause:
                logging.debug("    " * len(current_path) + "Using self as uncontrolled initial cause")
                combined_uncontrolled_initial_cause = LogicalExpression([make_symbol(self.uriref)])
            elif is_root_cause:
                logging.debug("    " * len(current_path) + "Using self as uncontrolled root cause")
                combined_uncontrolled_root_cause = LogicalExpression([make_symbol(self.uriref)])

        # Combine all the CSG reports from the parents and add in any from this Threat:
        combined_csg_reports |= csg_reports

        return Explanation(
            initial_cause=combined_initial_cause,
            root_cause=combined_root_cause,
            upstream_uncontrolled_likelihood=combined_upstream_uncontrolled_likelihood,
            local_uncontrolled_likelihood=self.local_uncontrolled_likelihood,
            cause_node_uris=combined_cause_node_uris,
            loopback_node_uris=combined_loopback_node_uris,
            csg_reports=combined_csg_reports,
            uncontrolled_initial_cause=combined_uncontrolled_initial_cause,
            uncontrolled_root_cause=combined_uncontrolled_root_cause,
            is_normal_effect=False
        )


class MisbehaviourSet(Entity):
    """Represents a Misbehaviour Set, or "Consequence" (a Misbehaviour at an Asset)."""
    def __init__(self, uriref, graph):
        super().__init__(uriref, graph)
        self.cached_explanations = []

    def __str__(self):
        return "Misbehaviour: {} ({})".format(self.comment, str(self.uriref))

    def _likelihood_uri(self):
        uriref = self.graph.value(self.uriref, HAS_PRIOR)
        if uriref is None:
            return None
        return uriref.split('/')[-1]

    def _impact_uri(self):
        uriref = self.graph.value(self.uriref, HAS_IMPACT)
        if uriref is None:
            return None
        return uriref.split('/')[-1]

    def _risk_uri(self):
        uriref = self.graph.value(self.uriref, HAS_RISK)
        if uriref is None:
            return None
        return uriref.split('/')[-1]

    def _domain_model_uri(self):
        uriref = self.graph.value(self.uriref, HAS_MISBEHAVIOUR)
        if uriref is None:
            return None
        return uriref.split('/')[-1]

    @property
    def label(self):
        """Return a misbehaviour label"""
        try:
            return dm_misbehaviours[self._domain_model_uri()]["label"]
        except KeyError:
            # might get here if the domain model CSVs are the wrong ones
            logging.warning("No MS label for " + str(self.uriref))
            return "**MS label**"

    @property
    def comment(self):
        """Return a short description of a misbehaviour"""
        likelihood = self.likelihood_label
        consequence = self.label
        asset_uri = self.graph.value(subject=self.uriref, predicate=LOCATED_AT)
        asset = self.graph.label(asset_uri)
        aspect = None
        if consequence.startswith("LossOf"):
            aspect = un_camel_case(consequence[6:])
            consequence = "loses"
        elif consequence.startswith("Loss Of"):
            aspect = un_camel_case(consequence[7:])
            consequence = "loses"
        elif consequence.startswith("Not"):
            aspect = un_camel_case(consequence[3:])
            consequence = "is not"
        if aspect != None:
            if not SHOW_LIKELIHOOD_IN_DESCRIPTION:
                return '"{}" {} {}'.format(un_camel_case(asset), consequence, aspect)
            else:
                return '{} likelihood that "{}" {} {}'.format(likelihood, un_camel_case(asset), consequence, aspect)
        else:
            if not SHOW_LIKELIHOOD_IN_DESCRIPTION:
                return '{} at {}'.format(un_camel_case(consequence), un_camel_case(asset))
            else:
                return '{} likelihood of: {} at {}'.format(likelihood, un_camel_case(consequence), un_camel_case(asset))

    @property
    def description(self):
        """Return a long description of a misbehaviour"""
        try:
            return dm_misbehaviours[self._domain_model_uri()]["description"]
        except KeyError:
            # might get here if the domain model CSVs are the wrong ones
            logging.warning("No MS description for " + str(self.uriref))
            return "**MS description**"

    @property
    def likelihood_number(self):
        return dm_likelihood_levels[self._likelihood_uri()]["number"]

    @property
    def likelihood_label(self):
        return dm_likelihood_levels[self._likelihood_uri()]["label"]

    @property
    def impact_number(self):
        return dm_impact_levels[self._impact_uri()]["number"]

    @property
    def impact_label(self):
        return dm_impact_levels[self._impact_uri()]["label"]

    @property
    def risk_number(self):
        return dm_risk_levels[self._risk_uri()]["number"]

    @property
    def risk_label(self):
        return dm_risk_levels[self._risk_uri()]["label"]

    @property
    def is_normal_op(self):
        return (self.uriref, IS_NORMAL_OP_EFFECT, Literal(True)) in self.graph

    @property
    def is_external_cause(self):
        # if the domain model doesn't support mixed cause Threats, then some MS may be external causes
        return (self.uriref, IS_EXTERNAL_CAUSE, Literal(True)) in self.graph

    @property
    def threat_parents(self):
        """Get all the Threats that can cause this Misbehaviour (disregarding likelihoods and untriggered Threats)"""
        threats = [self.graph.threat(t) for t in self.graph.subjects(CAUSES_MISBEHAVIOUR, self.uriref)]
        # TODO: it would be better to test if a threat had is_triggered and then check the threat's triggering CSGs to see if they were active
        # Easiest to just check the threat likelihood, but this relies on the risk calculation already being done
        return [threat for threat in threats if threat.likelihood_number >= 0]  # likelihood_number is set to -1 for untriggered threats

    @property
    def all_causes_are_normal_op(self):
        return all([threat.is_normal_op for threat in self.threat_parents])

    #TODO: move this method onto a special subclass of a more general Threat class

    def explain_likelihood(self, current_path=None):
        """Return an explanation of the likelihood of the MisbehaviourSet, given the path taken to get to the MisbehaviourSet. Return a cached result if there is a valid one."""

        if current_path is None:
            current_path = set()

        normal_op = " (normal operation)" if self.is_normal_op else ""
        logging.debug("    " * len(current_path) + "Explaining Misbehaviour: " + str(self.uriref) + " (" + self.comment + ")" + normal_op)

        # Keep a cache of results on self.

        # For each result in the cache, take the intersection of the current_path and the result's loopback_nodes.
        # If the intersection is the same as the loopback_nodes then we can reuse that cached result.
        # The reason being that the loopback_nodes are where the tree traversal was halted as it reached a node that
        # was already visited. We need to ensure that the same blocks will occur.

        # We also need to examine the nodes that were visited in a result. If any of them are in the current_path then
        # the result might be different as we'd be blocking the search in a different place and so the cached result cannot be used.

        # Basically, we have to block the search in the same places, and can't block it in new places.

        explanation = None

        for index, cached_explanation in enumerate(self.cached_explanations):
            if len(cached_explanation.loopback_node_uris.intersection(current_path)) == len(cached_explanation.loopback_node_uris) and len(cached_explanation.cause_node_uris.intersection(current_path)) == 0:
                logging.debug("    " * (len(current_path) + 1) + f"Reusing cached explanation {index}: {cached_explanation}")
                explanation = cached_explanation
                break

        # TODO: should be able to also cache failures (in Threat caching as well)

        if explanation is None:
            # If there was nothing in the cache we can use, do the calculation and save the result before returning it
            explanation = self._explain_likelihood(current_path)
            logging.debug("    " * (len(current_path) + 1) + f"New explanation {len(self.cached_explanations)}: {explanation}")
            self.cached_explanations.append(explanation)

        # If we are not the first node in the tree then return the (from-cached or newly-saved) explanation.
        # Otherwise, return a copy of all the csg_reports, adding in another one if there is an uncontrolled_initial_cause or uncontrolled_root_cause
        if len(current_path) > 0:
            return explanation
        else:
            logging.debug("Returning final answer")

            csg_reports = set()

            # if there is an uncontrolled_cause then add a CSG_report about it
            if explanation.uncontrolled_initial_cause != None or explanation.uncontrolled_root_cause != None:
                logging.debug("Adding uncontrolled cause report")
                csg_report = ControlStrategyReport(
                    control_strategy=None,
                    upstream_uncontrolled_likelihood=explanation.upstream_uncontrolled_likelihood,
                    local_uncontrolled_likelihood=explanation.local_uncontrolled_likelihood,
                    initial_cause=explanation.uncontrolled_initial_cause,
                    root_cause=explanation.uncontrolled_root_cause,
                    intermediate_cause=None,
                    misbehaviour=self)
                csg_reports.add(csg_report)
                logging.debug(str(csg_report))

            # make a copy of all the CSG_reports and add self to each one
            for csg_report in explanation.csg_reports:
                csg_report_copy = copy.copy(csg_report)
                csg_report_copy.misbehaviour = self
                csg_reports.add(csg_report_copy)

            return csg_reports

    def _explain_likelihood(self, current_path=None):
        """Return an explanation of the likelihood of the MisbehaviourSet, given the path taken to get to the MisbehaviourSet."""

        # make a copy of current_path, add self
        current_path = set(current_path)
        current_path.add(self.uriref)

        # A MisbehaviourSet can be at the top of the tree for two reasons:
        # 1. there is no Threat in the domain model which undermines it (e.g. "In Service" MS)
        # 2. there is a Threat in the domain model which undermines it but the Threat is not the system model

        # list to hold the parent return values
        parent_explanations = []

        # list to hold loopback_node_uris from catching exception
        combined_loopback_node_uris = set()

        # Find all parent Threats (could be none)
        parents = self.threat_parents
        
        if len(parents) == 0:
            # Nothing can cause this MisbehaviourSet: that's okay
            logging.debug("    " * len(current_path) + "Misbehaviour has no causes: " + str(self))
            # Return minimal explanation:
            return Explanation(
                initial_cause=None,
                root_cause=None,
                upstream_uncontrolled_likelihood=0,
                local_uncontrolled_likelihood=0,
                cause_node_uris=set([self.uriref]),
                loopback_node_uris=set(),
                csg_reports=set(),
                uncontrolled_initial_cause=None,
                uncontrolled_root_cause=None,
                is_normal_effect=False
            )

        # Combine and return undiscarded parent return values (could be none) =>
        #     OR(root_cause expressions)
        #     OR(initial_cause expressions)
        #     max(the upstream_uncontrolled_likelihood values)
        #     union(cause_node_uris)
        #       also adding self to the set
        #     union(loopback_node_uris) from both parent_return_values (good) and caught LoopbackErrors
        #       also removing self from the set to ensure the return value describes just the tree starting at self
        #     union(csg_reports)
        #       It is really an OR but we're just dropping that info.
        #     OR(uncontrolled_initial_cause expressions)
        #     OR(uncontrolled_root_cause expressions)

        for threat in parents:
            if threat.uriref not in current_path:
                # If the threat is not in the current path then we need to explain it
                try:
                    parent_explanation = threat.explain_likelihood(current_path)
                    # if upstream_uncontrolled_likelihood is >= the misbehaviour's likelihood, add the return value to the list
                    # otherwise there is never any way this parent could be the cause of this Misbehaviour
                    logging.debug("    " * len(current_path) + "Parent upstream_uncontrolled_likelihood: " + str(parent_explanation.upstream_uncontrolled_likelihood) + " / Misbehaviour likelihood: " + str(self.likelihood_number))
                    if parent_explanation.upstream_uncontrolled_likelihood >= self.likelihood_number:
                        parent_explanations.append(parent_explanation)
                    combined_loopback_node_uris |= parent_explanation.loopback_node_uris
                except LoopbackError as error:
                    combined_loopback_node_uris |= error.loopback_node_uris
            else:
                logging.debug("    " * len(current_path) + "Parent Threat on current path: " + str(threat.uriref))
                combined_loopback_node_uris.add(threat.uriref)

        combined_loopback_node_uris.discard(self.uriref)

        if len(parent_explanations) == 0:
            logging.debug("    " * len(current_path) + "Error: path is not viable; no parent Threats can be caused")
            raise LoopbackError(combined_loopback_node_uris)

        combined_cause_node_uris = set().union(*[ret.cause_node_uris for ret in parent_explanations])
        combined_cause_node_uris.add(self.uriref)

        combined_upstream_uncontrolled_likelihood = max([ret.upstream_uncontrolled_likelihood for ret in parent_explanations])

        if combined_upstream_uncontrolled_likelihood == 0:
            logging.debug("    " * len(current_path) + "Misbehaviour has zero max likelihood so cannot be the cause of anything")
            return Explanation(
                initial_cause=None,
                root_cause=None,
                upstream_uncontrolled_likelihood=0,
                local_uncontrolled_likelihood=self.likelihood_number,
                cause_node_uris=combined_cause_node_uris,
                loopback_node_uris=combined_loopback_node_uris,
                csg_reports=set(),
                uncontrolled_initial_cause=None,
                uncontrolled_root_cause=None,
                is_normal_effect=False
            )

        # To determined if a threat is a root cause (disregarding likelihood) we need to know if all its parents are normal effects.
        # We can't just use the is_normal_op property which reads from the predicate added in the risk calculation because it is also dependent on the likelihood calculation.
        # We therefore work out if each MisbehaviourSet is a normal effect (disregarding likelihood) and store it in the Explanation so that it can be accessed by the Threat._explain_likelihood().
        # It is tempting to store the result on the MisbehaviourSet object but it may be that it varies depending on the route taken to get to the MisbehaviourSet (not sure).
        is_extra_normal_effect = combined_upstream_uncontrolled_likelihood > 0 and self.all_causes_are_normal_op
        if is_extra_normal_effect:
            logging.debug("    " * len(current_path) + "Misbehaviour is an extra normal effect")
        is_normal_effect = self.is_normal_op or is_extra_normal_effect
    
        combined_root_cause = LogicalExpression.create_or_none([ret.root_cause for ret in parent_explanations], all_required=False)
        combined_initial_cause = LogicalExpression.create_or_none([ret.initial_cause for ret in parent_explanations], all_required=False)
        combined_uncontrolled_root_cause = LogicalExpression.create_or_none([ret.uncontrolled_root_cause for ret in parent_explanations], all_required=False)
        combined_uncontrolled_initial_cause = LogicalExpression.create_or_none([ret.uncontrolled_initial_cause for ret in parent_explanations], all_required=False)
        combined_csg_reports = set().union(*[ret.csg_reports for ret in parent_explanations])

        # For a Threat, the local_uncontrolled_likelihood is the likelihood of the Threat before the application of any active CSGs at the Threat
        # For a Misbehaviour, there are no CSGs so the local_uncontrolled_likelihood is just the likelihood from the risk calculation

        return Explanation(
            initial_cause=combined_initial_cause,
            root_cause=combined_root_cause,
            upstream_uncontrolled_likelihood=combined_upstream_uncontrolled_likelihood,
            local_uncontrolled_likelihood=self.likelihood_number,
            cause_node_uris=combined_cause_node_uris,
            loopback_node_uris=combined_loopback_node_uris,
            csg_reports=combined_csg_reports,
            uncontrolled_initial_cause=combined_uncontrolled_initial_cause,
            uncontrolled_root_cause=combined_uncontrolled_root_cause,
            is_normal_effect=is_normal_effect
        )

class Explanation:
    """Represents an explanation of the likelihood of a Threat or MisbehaviourSet."""
    def __init__(self, initial_cause, root_cause, upstream_uncontrolled_likelihood, local_uncontrolled_likelihood, cause_node_uris, loopback_node_uris, csg_reports, uncontrolled_initial_cause, uncontrolled_root_cause, is_normal_effect):
        # Logical expression of the initial cause
        self.initial_cause = initial_cause
        # Logical expression of the root cause
        self.root_cause = root_cause
        # The likelihood of the Threat or MisbehaviourSet, disregarding all control strategies
        self.upstream_uncontrolled_likelihood = upstream_uncontrolled_likelihood
        # The likelihood due to the parent(s) (Threat or MisbehaviourSet), disregarding any control strategies at this node
        self.local_uncontrolled_likelihood = local_uncontrolled_likelihood
        # Set of URIs of all nodes that are causes of the Threat or MisbehaviourSet (upstream in the attack tree)
        self.cause_node_uris = cause_node_uris
        # Set of URIs of all nodes that were encountered when exploring cause tree but which had been visited already in the path to this node
        self.loopback_node_uris = loopback_node_uris
        # Set of ControlStrategyReports that have been found at this node or its attack tree
        self.csg_reports = csg_reports
        # Logical expression of the uncontrolled initial causes if there are any uncontrolled paths
        self.uncontrolled_initial_cause = uncontrolled_initial_cause
        # Logical expression of the uncontrolled root causes if there are any uncontrolled paths
        self.uncontrolled_root_cause = uncontrolled_root_cause
        # Whether this node is a normal effect (i.e. a MisbehaviourSet in the normal operation graph), disregarding likelihood
        self.is_normal_effect = is_normal_effect

    def __str__(self):
        return "initial_cause: " + str(self.initial_cause) + " / root cause: " + str(self.root_cause) + " / upstream_uncontrolled_likelihood: " + str(self.upstream_uncontrolled_likelihood) + " / csg_reports: " + str(len(self.csg_reports)) + " / cause_node_uris: " + str(len(self.cause_node_uris)) + " / loopback_node_uris: " + str(len(self.loopback_node_uris)) + " / uncontrolled_initial_cause: " + str(self.uncontrolled_initial_cause) + " / uncontrolled_root_cause: " + str(self.uncontrolled_root_cause)

class ControlStrategyReport():
    """Represents a Control Strategy Report, used when we want to report something about the utility of a CSG."""
    def __init__(self, control_strategy, upstream_uncontrolled_likelihood, local_uncontrolled_likelihood, initial_cause, root_cause, intermediate_cause, misbehaviour=None):
        # the system model CSG
        self.control_strategy = control_strategy
        # the likelihood if there are no CSGs in place
        self.upstream_uncontrolled_likelihood = upstream_uncontrolled_likelihood
        # the likelihood if this CSG at this Threat (intermediate cause) is not in place
        self.local_uncontrolled_likelihood = local_uncontrolled_likelihood
        # the initial cause as a logical expression
        self.initial_cause = initial_cause
        # the root cause as a logical expression
        self.root_cause = root_cause
        # the intermediate cause threat - this is the threat that the CSG is addressing
        self.intermediate_cause = intermediate_cause
        # the MisbehaviourSet that was being analysed when this CSG was found
        self.misbehaviour = misbehaviour

    def __str__(self):
        return "Control Strategy Report: [{}] / [Initial Cause: {}] / [Root Cause: {}] / [Intermediate Cause: {}] / Global Uncontrolled Likelihood: {} / Local Uncontrolled Likelihood: {} / Misbehaviour Set: {}".format(
            str(self.control_strategy), str(self.initial_cause), str(self.root_cause), str(self.intermediate_cause), self.upstream_uncontrolled_likelihood, self.local_uncontrolled_likelihood, str(self.misbehaviour))

    def __hash__(self):
        return hash((self.control_strategy, self.upstream_uncontrolled_likelihood, self.local_uncontrolled_likelihood, self.root_cause, self.initial_cause, self.intermediate_cause, self.misbehaviour))

    def __eq__(self, other):
        if not isinstance(other, ControlStrategyReport):
            return False
        return (self.control_strategy == other.control_strategy and
                self.upstream_uncontrolled_likelihood == other.upstream_uncontrolled_likelihood and
                self.local_uncontrolled_likelihood == other.local_uncontrolled_likelihood and
                self.initial_cause == other.initial_cause and
                self.root_cause == other.root_cause and
                self.intermediate_cause == other.intermediate_cause and
                self.misbehaviour == other.misbehaviour)

    def split_root_causes(self):
        """Return a list of ControlStrategyReports with the root cause split into its DNF OR terms"""
        if self.root_cause is None:
            yield self
        else:
            for root_cause in self.root_cause.dnf_terms:
                csr = copy.copy(self)
                csr.root_cause = LogicalExpression([root_cause])
                yield csr

    def additional_comment(self):
        if self.control_strategy is None:
            return "There are no controls on this path"
        else:
            if self.is_over_effective:
                return "This control is over-effective"  # something else means the likelihood is higher than this achieves
            else:
                return "This control is effective"

    @property
    def is_backstop(self):
        """Return whether this CSG is a backstop control, i.e. whether something else upstream brought the likelihood down to at or below the target"""
        return self.misbehaviour.likelihood_number >= self.local_uncontrolled_likelihood

    @property
    def is_over_effective(self):
        """Return whether this CSG is over-effective, i.e. whether something else downstream causes the likelihood to be higher than the effect of this CSG"""
        return self.misbehaviour.likelihood_number > self.control_strategy.maximum_likelihood

    @property
    def is_valid(self):
        """Return whether this CSG makes sense given the likelihood of the target and the root cause"""
        return self.control_strategy is None or (self.upstream_uncontrolled_likelihood > self.misbehaviour.likelihood_number and self.misbehaviour.likelihood_number >= self.control_strategy.maximum_likelihood)

    @classmethod
    def cvs_header(cls):
        columns = ["Initial Cause", "Root Cause", "Intermediate Cause", "Consequence",
                "Impact", "Likelihood", "Risk",
                "Control", "Residual Likelihood", "Residual Risk", "Degree", "Comment"]

        if args["hide_initial_causes"]:
            return columns[1:]
        else:
            return columns
        
    def csv_row(self, graph):
        initial = "None" if self.initial_cause is None else self.initial_cause.pretty_print()
        if self.root_cause is None:
            root = "None"
        else:
            if len(self.root_cause.uris) == 1:
                threat = graph.threat(list(self.root_cause.uris)[0])
                root = threat.comment
            else:
                root = self.root_cause.pretty_print()

        if self.intermediate_cause is None:
            intermediate = "None"
        else:
            intermediate = self.intermediate_cause.comment
            # if self.root_cause.pretty_print() == self.intermediate_cause.comment:
            #     intermediate = ""
            if self.intermediate_cause.is_normal_op:
                intermediate += " (Normal Operation)"

        impact = self.misbehaviour.impact_number
        likelihood = self.local_uncontrolled_likelihood
        risk = dm_risk_lookup[impact][likelihood]

        degree = "Secondary" if self.is_backstop else "Primary"
        comment = self.additional_comment()

        if self.control_strategy is None:
            control_strategy = "None"
            residual_likelihood = self.local_uncontrolled_likelihood
            residual_risk = risk
        else:
            control_strategy = self.control_strategy.description
            residual_likelihood = self.control_strategy.maximum_likelihood
            residual_risk = dm_risk_lookup[impact][residual_likelihood]

        columns = [initial, root, intermediate, self.misbehaviour.comment,
                impact, likelihood, risk,
                control_strategy, residual_likelihood, residual_risk,
                degree, comment]

        if args["hide_initial_causes"]:
            return columns[1:]
        else:
            return columns

class Timer():
    def __init__(self):
        self.stime = time.perf_counter()

    def log(self):
        etime = time.perf_counter()
        logging.info(f"-- Duration: {etime - self.stime:0.2f} seconds")
        self.stime = time.perf_counter()


#
# TODO: This block of code needs to be incorporated into the Entity subclasses or deleted
#

def get_threat_direct_cause_uris(threat_uri):
    """Return a list of urirefs which are the direct causes (misbehaviours) of a threat"""
    direct_cause_uris = []
    for direct_cause in rdf_graph.subjects(CAUSES_THREAT, threat_uri):
        direct_cause_uris.append(direct_cause)
    return direct_cause_uris

def get_misbehaviour_direct_cause_uris(misb_uri):
    """Return a list of urirefs which are the direct causes (threats) of a misbehaviour"""
    direct_cause_uris = []
    for threat in rdf_graph.subjects(CAUSES_DIRECT_MISBEHAVIOUR, misb_uri):
        direct_cause_uris.append(threat)
    return direct_cause_uris

def get_is_misbehaviour_on_asserted_asset(ms_uriref):
    """Return Boolean describing if the uriref refers to a misbehaviour located at an asserted asset"""
    if get_is_threat(ms_uriref):
        return False
    else:
        for asset_uriref in rdf_graph.objects(ms_uriref, LOCATED_AT):
            if get_is_asserted_asset(asset_uriref):
                return True
        return False

def get_is_asserted_asset(asset_uriref):
    """Return Boolean describing whether the uriref refers to an asserted asset"""
    # There should only be 1 triple matching this, but I can't see another way to just query the asserted graph
    for dummy, dummy, type in rdf_graph.triples((asset_uriref, HAS_TYPE, None, asserted_graph)):
        if type.startswith(DOMAIN):
            return True
    return False

def get_is_in_service(threat_uriref):
    for cause_uriref in rdf_graph.subjects(CAUSES_THREAT, threat_uriref):
        if get_is_default_tw(cause_uriref):
            return True
    return False

def get_misbehaviour_location_uri(ms_uriref):
    """Return the asset URIs that the misbehaviour has an effect on"""
    if not get_is_threat(ms_uriref):
        return rdf_graph.value(ms_uriref, LOCATED_AT)

def get_threat_involved_asset_uris(threat_uriref):
    """Return a list of urirefs of the assets that are in a threat's matching pattern"""
    assets = []
    for matching_pattern in rdf_graph.objects(threat_uriref, APPLIES_TO):
        for node in rdf_graph.objects(matching_pattern, HAS_NODE):
            for asset in rdf_graph.objects(node, HAS_ASSET):
                assets.append(asset)
    return assets

def get_cs_comment(cs_uri):
    control_uri = rdf_graph.value(cs_uri, HAS_CONTROL)
    control_label = un_camel_case(dm_controls[control_uri.split('/')[-1]]["label"])
    asset_uri = rdf_graph.value(cs_uri, LOCATED_AT)
    asset_label = rdf_graph.value(asset_uri, HAS_LABEL)
    if asset_label[0] != "[": asset_label = '"' + asset_label + '"'
    return control_label + " at " + asset_label

#
# end block
#


def unzip_gz_file(filename):
    if not filename.lower().endswith('.gz'):
        return filename

    # Create a temporary file to store the unzipped data
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_filename = temp_file.name

    try:
        # Open the gzipped file and the temporary file
        with gzip.open(filename, 'rb') as gz_file, open(temp_filename, 'wb') as temp:
            # Read from the gzipped file and write to the temporary file
            temp.write(gz_file.read())

        logging.info(f"Unzipped NQ file into temporary file: {temp_filename}")
        return temp_filename

    except Exception as e:
        logging.error(f"Error while unzipping: {e}")

# TODO: make a domain model class to hold this data

def inverse(level):
    """Convert between trustworthiness and likelihood levels"""
    # TODO: the "5" should not be hard-coded here
    return 5 - level

logging.info("Loading domain model misbehaviours...")
dm_misbehaviours = load_domain_misbehaviours(domain_misbehaviours_filename)

logging.info("Loading domain model trustworthiness attributes...")
dm_trustworthiness_attributes = load_domain_trustworthiness_attributes(domain_trustworthiness_attributes_filename)

logging.info("Loading domain model controls...")
dm_controls = load_domain_controls(domain_controls_filename)

logging.info("Loading domain model control strategies...")
dm_control_strategies = load_domain_control_strategies(domain_control_strategies_filename)

logging.info("Loading domain model CA Settings...")
dm_ca_settings = load_domain_ca_settings(domain_ca_settings_filename)

logging.info("Loading domain model levels...")
dm_likelihood_levels = load_domain_levels(domain_likelihood_levels_filename)
dm_trustworthiness_levels = load_domain_levels(domain_trustworthiness_levels_filename)
dm_impact_levels = load_domain_levels(domain_impact_levels_filename)
dm_risk_levels = load_domain_levels(domain_risk_levels_filename)

logging.info("Loading risk lookup table...")
dm_risk_lookup = load_risk_lookup(domain_risk_lookup_filename)

logging.info("Loading nq file...")
timer = Timer()
system_model = Graph(nq_filename)
timer.log()


target_ms = set()

if target_ms_uris:
    for ms_uri in target_ms_uris:
        target_ms.add(system_model.misbehaviour(URIRef(SYSTEM + "#" + ms_uri)))
else:
    logging.info("High impact consequences:")
    for ms in system_model.misbehaviours:
        # TODO: factor out this magic number
        if ms.impact_number > 3:
            logging.info(ms.comment)
            target_ms.add(ms)

    logging.info("High risk consequences:")
    for ms in system_model.misbehaviours:
        # TODO: factor out this magic number
        if ms.risk_number > 3:
            logging.info(ms.comment)
            target_ms.add(ms)

all_csg_reports = set()

# TODO: could stop the search when all CSG-Threat pairs have been found?

logging.info("Computing explanations...")
for ms in target_ms:
    all_csg_reports |= ms.explain_likelihood()
    timer.log()

if args["simple_root_causes"]:
    # make a new empty set, then iterate through all_csg_reports, splitting each report as necessary and adding the new reports to the new set
    new_csg_reports = set()
    for csg_report in all_csg_reports:
        new_csg_reports |= set(csg_report.split_root_causes())
    all_csg_reports = new_csg_reports

with open(output_filename, 'w', newline='') as file:
    writer = csv.writer(file)
    # Write the header
    writer.writerow(ControlStrategyReport.cvs_header())
    # Write each row
    for csg_report in all_csg_reports:
        if csg_report.is_valid:
            writer.writerow(csg_report.csv_row(system_model))  # have to pass in system_model in order to create Threat from URI in LogicalExpression and get its description :-(

# for threat in system_model.threats:
#     logging.debug(str(threat))
#     for explanation in threat.likelihood_explanations:
#         logging.debug("    " + str(explanation))

# for ms in system_model.misbehaviours:
#     logging.debug(str(ms))
#     for explanation in ms.likelihood_explanations:
#         logging.debug("    " + str(explanation))