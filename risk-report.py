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
# from graphviz import Digraph
from rdflib import ConjunctiveGraph, Literal, URIRef

VERSION = "1.0"

algebra = boolean.BooleanAlgebra()
TRUE, FALSE, NOT, AND, OR, symbol = algebra.definition()

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

parser = argparse.ArgumentParser(description="Generate risk reports for Spyderisk system models",
                                 epilog="e.g. risk-report.py -i SteelMill.nq.gz -o steel.pdf -d ../domain-network/csv/ -m MS-LossOfControl-f8b49f60")
parser.add_argument("-i", "--input", dest="input", required=False, metavar="input_NQ_filename", help="Filename of the validated system model NQ file (compressed or not)")
parser.add_argument("-o", "--output", dest="output", required=False, metavar="output_csv_filename", help="Output CSV filename")
parser.add_argument("-d", "--domain", dest="csvs", required=False, metavar="CSV_directory", help="Directory containing the domain model CSV files")
# parser.add_argument("-m", "--misbehaviour", dest="misbehaviours", required=False, nargs="+", metavar="URI_fragment", help="Target misbehaviour IDs, e.g. 'MS-LossOfControl-f8b49f60'")
parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)

raw = parser.parse_args()
args = vars(raw)

# TODO: remove the defaults and make the arguments required
# nq_filename = args["input"] or './example-models/small 2024-05-08T14_32.nq.gz'
# csv_directory = args["csvs"] or  '../domain-network/csv/'
# # target_ms_ids = args["misbehaviours"] or ['MS-LossOfAvailability-c736a681']

nq_filename = args["input"] or './example-models/Steel Mill 2 blocks+ 2023-11-06T15_04.nq.gz'
csv_directory = args["csvs"] or  '../domain-network/csv/'
# target_ms_ids = args["misbehaviours"] or ['MS-LossOfControl-f8b49f60']

output_filename = args["output"] or 'output.csv'

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
MISBEHAVIOUR_SET = URIRef(CORE + "#MisbehaviourSet")
MITIGATES = URIRef(CORE + "#mitigates")
BLOCKS = URIRef(CORE + "#blocks")
HAS_CONTROL_SET = URIRef(CORE + "#hasControlSet")
HAS_MANDATORY_CONTROL_SET = URIRef(CORE + "#hasMandatoryCS")
CONTROL_SET = URIRef(CORE + "#ControlSet")
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
    return system_model.get_entity(URIRef(SYSTEM + "#" + frag_match.group()[8:-2])).comment

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

    def __str__(self):
        return self.pretty_print()

    def __eq__(self, other):
        return self.cause == other.cause

    def __hash__(self) -> int:
        return hash(self.cause)

    @property
    def uris(self):
        return set([URIRef(SYSTEM + "#" + str(symbol)) for symbol in self.cause.get_symbols()])

    def pretty_print(self, max_complexity=30):
        if self.cause is None:
            return "-None-"
        cause_complexity = str(self.cause.args).count("Symbol")
        if cause_complexity <= max_complexity:
            cause = algebra.dnf(self.cause.simplify())
            symb = re.compile(r'Symbol\(\'.*?\'\)')
            cause = symb.sub(get_comment_from_match, cause.pretty())
        else:
            cause = "Complexity: " + str(cause_complexity)
        return cause

class TreeTraversalError(Exception):
    """Exception raised when encountering an error during tree traversal."""
    def __init__(self, loopback_node_uris: set = None) -> None:
        """
        Initialize the TreeTraversalError exception.

        Args:
            loopback_node_uris (set): Set of URIs of nodes causing the loopback.
        """
        if loopback_node_uris is None:
            loopback_node_uris = set()
        self.loopback_node_uris = loopback_node_uris

    def __str__(self) -> str:
        return f"Error encountered during tree traversal. Loopback nodes: {self.loopback_node_uris}"

# TODO: Add the domain model as a parameter? And load from NQ rather than CSV files?
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
        return inverse(self.effectiveness_number)

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
        return sorted([self.graph.label(asset_uriref) for asset_uriref in self.control_set_asset_urirefs()])

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
        tw_level = self.get_inferred_level_label
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
        self.likelihood_explanations = []

    def __str__(self):
        return "Threat: {} ({})".format(self.comment, str(self.uriref))

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

    def _get_threat_comment(self):
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
    def comment(self):
        """Return the first part of the threat description (up to the colon) and add in the likelihood if so configured"""
        comment = self._get_threat_comment()
        comment = comment.replace('re-disabled at "Router"', 're-enabled at "Router"')  # hack that is necessary to correct an error in v6a3-1-4 for the overview paper system model
        if not SHOW_LIKELIHOOD_IN_DESCRIPTION:
            return comment
        else:
            return '{} likelihood of: {}'.format(self.likelihood_label, comment)

    @property
    def description(self):
        """Return the longer description of a threat (after the colon)"""
        short_comment = self._get_threat_comment()
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
    def secondary_threat_misbehaviour_parents(self):
        """Get all the Misbehaviours that can cause this Threat (disregarding likelihoods), for secondary Threat types"""
        ms_urirefs = self.graph.objects(self.uriref, HAS_SECONDARY_EFFECT_CONDITION)
        return [self.graph.misbehaviour(ms_uriref) for ms_uriref in ms_urirefs]

    @property
    def misbehaviour_parents(self):
        """Get all the Misbehaviours that can cause this Threat (disregarding likelihoods), for all Threat types"""
        return self.primary_threat_misbehaviour_parents + self.secondary_threat_misbehaviour_parents

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

    def explain_likelihood(self, current_path=None):
        if current_path is None:
            current_path = ()

        logging.debug("  " * len(current_path) + "Explaining Threat: " + str(self.uriref))

        for explanation in self.likelihood_explanations:
            if len(explanation["loopback_node_uris"].intersection(current_path)) == len(explanation["loopback_node_uris"]) and len(explanation["cause_node_uris"].intersection(current_path)) == 0:
                logging.debug("  " * len(current_path) + "  Reusing cached explanation")
                return explanation
        # If there was nothing in the cache we can use, do the calculation and save the result before returning it
        explanation = self._explain_likelihood(current_path)
        self.likelihood_explanations.append(explanation)
        return explanation
    
    def _explain_likelihood(self, current_path):
        # make a copy of current_path, add self
        current_path = set(current_path)
        current_path.add(self.uriref)

        # A Threat is an "initial cause" if all the TrustworthinessAttributeSets that cause it are "external causes" and it is a normal-op.
        #  The isInitialCause predicate is different.
        # A Threat is a "root cause" if it is not a normal-op (it is an "adverse" threat), it has TWAS, it would not be undermined by the maximum likelihood of its parent causes, and it has a non-zero likelihood
        #  The isRootCause predicate cannot be used for this because its placement depends on the likelihood calculation and this analysis is considering what happens without some CSGs so we cannot use this.
        # A Threat is an "intermediate cause" if there is an effective control strategy at it. These threats are set as attributes of the ControlStrategyReports

        # Examine all parent Misbehaviours (of both primary and secondary Threats) that are not already in the current path
        # Put the returned tuples in parent_return_values
        # A Threat requires all of its causes to be on good paths
        parent_return_values = []
        parents = self.misbehaviour_parents
        for ms in parents:
            if ms.uriref not in current_path:
                parent_return_values.append(ms.explain_likelihood(current_path))  # may throw an exception
            else:
                logging.debug("  " * len(current_path) + "Parent Misbehaviour is on current path: " + str(ms.uriref))
                raise TreeTraversalError([ms.uriref])

        # Store the parent likelihoods so we can find the minimum one (the "input" likelihood without local CSGs)
        parent_likelihoods = []

        # To compute the inferred_uncontrolled_likelihood:
        #   For a primary threat it's the entry-point TWASs' inferred values we need to look at.
        #     The inferred TWAS levels will have taken into account the asserted levels and the inferred likelihoods of the causing misbehaviours.
        #   For a secondary threat it's the likelihood of the causal misbehaviour.
        #   We need to take into account that threats can have mixed causes (so can be both "primary" and "secondary").

        inferred_twas_levels = [twas.inferred_level_number for twas in self.trustworthiness_attribute_sets]
        parent_likelihoods = [inverse(level) for level in inferred_twas_levels]
        logging.debug("  " * len(current_path) + "Likelihoods from inferred TWAS levels: " + str(parent_likelihoods))

        parent_likelihoods += [ms.likelihood_number for ms in self.secondary_threat_misbehaviour_parents]
        logging.debug("  " * len(current_path) + "All parent likehoods: " + str(parent_likelihoods))

        uncontrolled_inferred_likelihood = min(parent_likelihoods)

        # Combine and return parent return values:
        #     min(the max_likelihood values) combined with the uncontrolled_inferred_likelihood
        #     AND(root_cause expressions) or self if self is root_cause
        #     AND(initial_cause expressions) or self if self is initial_cause
        #     union of all cause_node_uris sets
        #       also adding self to the set
        #     union of all loopback_node_uris sets
        #       also removing self from the set to ensure the return value describes just the tree starting at self

        combined_parent_likelihood = min([ret["max_likelihood"] for ret in parent_return_values])  # TODO: check this again!
        combined_max_likelihood = max(combined_parent_likelihood, uncontrolled_inferred_likelihood)

        parents_are_normal_op = all([ret["is_normal_op"] for ret in parent_return_values])  # are all parents normal_ops?

        asserted_twas_levels = [twas.asserted_level_number for twas in self.trustworthiness_attribute_sets]
        if len(asserted_twas_levels):
            asserted_likelihood = min([inverse(level) for level in asserted_twas_levels])

        # We need a different root cause definition to the meaning of the predicate added in the risk calculation
        # TODO: include secondary threats as well
        is_root_cause = len(asserted_twas_levels) and combined_max_likelihood <= asserted_likelihood and not self.is_normal_op and asserted_likelihood > 0
        if is_root_cause:
            logging.debug("  " * len(current_path) + "Threat is root cause")
            combined_root_cause = LogicalExpression([make_symbol(self.uriref)])
        else:            
            combined_root_cause = LogicalExpression([ret["root_cause"] for ret in parent_return_values], all_required=True)

        combined_is_normal_op = parents_are_normal_op and self.is_normal_op  # parents + self (to return)

        # We need a different initial cause definition to the meaning of the predicate added in the risk calculation
        # TODO: include secondary threats as well
        if all([twas.is_external_cause for twas in self.trustworthiness_attribute_sets]) and self.is_normal_op and combined_max_likelihood > 0:
            logging.debug("  " * len(current_path) + "Threat is initial cause: " + str(self))
            combined_initial_cause = LogicalExpression([make_symbol(self.uriref)])
        else:
            combined_initial_cause = LogicalExpression([ret["initial_cause"] for ret in parent_return_values], all_required=True)

        combined_cause_node_uris = set().union(*[ret["cause_node_uris"] for ret in parent_return_values])
        combined_cause_node_uris.add(self.uriref)
        combined_loopback_node_uris = set().union(*[ret["loopback_node_uris"] for ret in parent_return_values])
        combined_loopback_node_uris.discard(self.uriref)

        csg_reports = set()
        if uncontrolled_inferred_likelihood > self.likelihood_number:
            # Some CSG(s) at this Threat have made a difference to the likelihood.
            # Make the CSG Report objects.
            # Note: the effective CSG could be on a normal_op Threat
            for csg in self.control_strategies:
                logging.debug("  " * len(current_path) + "Candidate Control Strategy: " + csg.description + ", active " + str(csg.is_active) + ", max likelihood: " + str(csg.maximum_likelihood))
                if csg.maximum_likelihood <= uncontrolled_inferred_likelihood and csg.is_active:
                    # this CSG is effective / at least prevents the likelihood being any higher
                    logging.debug("  " * len(current_path) + "Control Strategy is effective: " + str(csg))
                    csg_report = ControlStrategyReport(
                        control_strategy=csg, uncontrolled_likelihood=uncontrolled_inferred_likelihood, 
                        initial_cause=combined_initial_cause, root_cause=combined_root_cause, intermediate_cause=self)
                    csg_reports.add(csg_report)
                    logging.debug("  " * len(current_path) + str(csg_report))

        combined_csg_reports = set().union(*[ret["csg_reports"] for ret in parent_return_values])
        combined_csg_reports |= csg_reports
        logging.debug("  " * len(current_path) + "max_likelihood: " + str(combined_max_likelihood) + " / csg_reports: " + str(len(combined_csg_reports)) + " / cause_node_uris: " + str(len(combined_cause_node_uris)) + " / loopback_node_uris: " + str(len(combined_loopback_node_uris)) + " / normal_op: " + str(combined_is_normal_op))
        return {
            "max_likelihood": combined_max_likelihood,
            "root_cause": combined_root_cause,
            "is_normal_op": combined_is_normal_op,  # TODO: this attribute is not actually used for anything so should be removed
            "initial_cause": combined_initial_cause,
            "csg_reports": combined_csg_reports,
            "cause_node_uris": combined_cause_node_uris,
            "loopback_node_uris": combined_loopback_node_uris
        }


class MisbehaviourSet(Entity):
    """Represents a Misbehaviour Set, or "Consequence" (a Misbehaviour at an Asset)."""
    def __init__(self, uriref, graph):
        super().__init__(uriref, graph)
        self.likelihood_explanations = []

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

    #TODO: move this method onto a special subclass of a more general Threat class
    def explain_likelihood(self, current_path=None):
        if current_path is None:
            current_path = set()

        logging.debug("  " * len(current_path) + "Explaining Misbehaviour: " + str(self.uriref))

        # Keep a cache of results on self.

        # For each result in the cache, take the intersection of the current_path and the result's loopback_nodes.
        # If the intersection is the same as the loopback_nodes then we can reuse that cached result.
        # The reason being that the loopback_nodes are where the tree traversal was halted as it reached a node that
        # was already visited. We need to ensure that the same blocks will occur.

        # We also need to examine the nodes that were visited in a result. If any of them are in the current_path then
        # the result might be different as we'd be blocking the search in a different place and so the cached result cannot be used.

        # Basically, we have to block the search in the same places, and can't block it in new places.

        for explanation in self.likelihood_explanations:
            if len(explanation["loopback_node_uris"].intersection(current_path)) == len(explanation["loopback_node_uris"]) and len(explanation["cause_node_uris"].intersection(current_path)) == 0:
                logging.debug("  " * len(current_path) + "  Reusing cached explanation")
                return explanation
        # If there was nothing in the cache we can use, do the calculation and save the result before returning it
        explanation = self._explain_likelihood(current_path)
        self.likelihood_explanations.append(explanation)
        return explanation

    def _explain_likelihood(self, current_path=None):
        # make a copy of current_path, add self
        current_path = set(current_path)
        current_path.add(self.uriref)

        # A MisbehaviourSet can be at the top of the tree for two reasons:
        # 1. there is no Threat in the domain model which undermines it (e.g. "In Service" MS)
        # 2. there is a Threat in the domain model which undermines it but the Threat is not the system model

        # list to hold the parent return values
        parent_return_values = []

        # list to hold loopback_node_uris from catching exception
        loopback_node_uri_sets = []

        # Find all parent Threats (could be none)
        parents = self.threat_parents

        for threat in parents:
            if threat.uriref not in current_path:
                # If the threat is not in the current path then we need to explain it
                try:
                    parent_return_value = threat.explain_likelihood(current_path)
                    # if max_likelihood is >= the misbehaviour's likelihood, add the return value to the list
                    if parent_return_value["max_likelihood"] >= self.likelihood_number:
                        parent_return_values.append(parent_return_value)
                except TreeTraversalError as error:
                    logging.debug("  " * len(current_path) + "TreeTraversalError when Explaining Threat: " + str(threat.uriref))
                    loopback_node_uri_sets.append(error.loopback_node_uris)
            else:
                logging.debug("  " * len(current_path) + "Parent Threat on current path: " + str(threat.uriref))

        if len(parent_return_values) == 0:
            # there were no parents (or none that we had not already visited), so nothing is causing this Misbehaviour
            # raise TreeTraversalError()
            logging.debug("  " * len(current_path) + "Misbehaviour is at the top of the tree: " + str(self))
            # Use "None" as initial_cause: this is picked up in Threat.explain() and the Threat is then used as the initial cause
            logging.debug("  " * len(current_path) + "max_likelihood: " + str(self.likelihood_number) + " / csg_reports: 0" + " / cause_node_uris: 1" + " / loopback_node_uris: 0" + " / normal_op: " + str(self.is_normal_op))
            return {
                "max_likelihood": self.likelihood_number, 
                "root_cause": None,
                "is_normal_op": self.is_normal_op,
                "initial_cause": None,
                "csg_reports": [],
                "cause_node_uris": set([self.uriref]),
                "loopback_node_uris": set()
            }

        # Combine and return undiscarded parent return values (could be none) =>
        #     max(the max_L values)
        #     OR(root_cause expressions)
        #     OR(initial_cause expressions)
        #     union of all cause_node_uris sets
        #       also adding self to the set
        #     union of all loopback_node_uris sets from both parent_return_values (good) and loopback_node_uri_sets (errors)
        #       also removing self from the set to ensure the return value describes just the tree starting at self
        #     list of csg_reports
        #       It is really an OR. Just flatten this?!
        #     union of loopback_nodes (removing self if it's in there)
        #     true if all of the parents were normal_ops and self is normal_op
        combined_max_likelihood = max([ret["max_likelihood"] for ret in parent_return_values])
        combined_root_cause = LogicalExpression([ret["root_cause"] for ret in parent_return_values], all_required=False)
        combined_initial_cause = LogicalExpression([ret["initial_cause"] for ret in parent_return_values], all_required=False)
        combined_csg_reports = set().union(*[ret["csg_reports"] for ret in parent_return_values])
        combined_cause_node_uris = set().union(*[ret["cause_node_uris"] for ret in parent_return_values])
        combined_cause_node_uris.add(self.uriref)
        combined_loopback_node_uris = set().union(*[ret["loopback_node_uris"] for ret in parent_return_values])
        combined_loopback_node_uris |= set().union(*loopback_node_uri_sets)
        combined_loopback_node_uris.discard(self.uriref)
        combined_is_normal_op = all([ret["is_normal_op"] for ret in parent_return_values]) and self.is_normal_op
        logging.debug("  " * len(current_path) + "max_likelihood: " + str(combined_max_likelihood) + " / csg_reports: " + str(len(combined_csg_reports)) + " / cause_node_uris: " + str(len(combined_cause_node_uris)) + " / loopback_node_uris: " + str(len(combined_loopback_node_uris)) + " / normal_op: " + str(combined_is_normal_op))
        return {
            "max_likelihood": combined_max_likelihood,
            "root_cause": combined_root_cause,
            "is_normal_op": combined_is_normal_op,
            "initial_cause": combined_initial_cause,
            "csg_reports": combined_csg_reports,
            "cause_node_uris": combined_cause_node_uris,
            "loopback_node_uris": combined_loopback_node_uris
        }
    
class ControlStrategyReport():
    """Represents a Control Strategy Report."""
    def __init__(self, control_strategy, uncontrolled_likelihood, root_cause, intermediate_cause, initial_cause):
        self.control_strategy = control_strategy
        self.uncontrolled_likelihood = uncontrolled_likelihood
        self.root_cause = root_cause
        self.initial_cause = initial_cause
        self.intermediate_cause = intermediate_cause
        self.misbehaviour = None

    def __str__(self):
        return "Control Strategy Report: [{}] / [Initial Cause: {}] / [Root Cause: {}] / [Intermediate Cause: {}] / Uncontrolled Likelihood: {}".format(
            str(self.control_strategy), str(self.initial_cause), str(self.root_cause), str(self.intermediate_cause), self.uncontrolled_likelihood)

    def __hash__(self):
        return hash((self.control_strategy, self.uncontrolled_likelihood, self.root_cause, self.intermediate_cause, self.misbehaviour))

    def __eq__(self, other):
        if not isinstance(other, ControlStrategyReport):
            return False
        return (self.control_strategy == other.control_strategy and
                self.uncontrolled_likelihood == other.uncontrolled_likelihood and
                self.root_cause == other.root_cause and
                self.intermediate_cause == other.intermediate_cause and
                self.misbehaviour == other.misbehaviour)

    def additional_comment(self):
        if self.control_strategy.maximum_likelihood == self.uncontrolled_likelihood:
            # back-stop: something upstream has brought likelihood down and this brings it down to the same level
            return "This is not itself reducing the likelihood but does not let the likelihood exceed the current value"
        else:
            if self.control_strategy.maximum_likelihood == self.misbehaviour.likelihood_number:
                # this CSG is the one that brings the likelihood down
                return "This is the cause of the reduction in likelihood"
            elif self.control_strategy.maximum_likelihood < self.misbehaviour.likelihood_number:
                # does more than needed, but something else brings likelihood up
                return "Other higher likelihood causes take precedence"
            else:
                # under controlled
                return "Other lower likelihood causes are also required"

    @classmethod
    def cvs_header(cls):
        return ["Initial Cause", "Root Cause", "Intermediate Cause", "Consequence",
                "Likelihood", "Impact", "Risk",
                "Control", "Residual Likelihood", "Residual Risk", "Comment"]

    def csv_row(self):
        intermediate = self.intermediate_cause.comment
        # if self.root_cause.pretty_print() == self.intermediate_cause.comment:
        #     intermediate = ""
        if self.intermediate_cause.is_normal_op:
            intermediate += " (normal operation)"
        return [self.initial_cause.pretty_print(), self.root_cause.pretty_print(), intermediate, self.misbehaviour.comment,
                self.uncontrolled_likelihood, self.misbehaviour.impact_number, dm_risk_lookup[self.misbehaviour.impact_number][self.uncontrolled_likelihood],
                self.control_strategy.description, self.control_strategy.maximum_likelihood, dm_risk_lookup[self.misbehaviour.impact_number][self.control_strategy.maximum_likelihood],
                self.additional_comment()]

class Timer():
    def __init__(self):
        self.stime = time.perf_counter()

    def log(self):
        etime = time.perf_counter()
        print(f"-- Duration: {etime - self.stime:0.2f} seconds")
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
print(len(system_model))
timer.log()


# TODO: if CLI option target_ms is set then use that, otherwise get the high impact & high risk ones as below

target_ms = set()

logging.info("High impact consequences:")
for ms in system_model.misbehaviours:
    if ms.impact_number > 3:
        logging.info(ms.comment)
        target_ms.add(ms)

logging.info("High risk consequences:")
for ms in system_model.misbehaviours:
    if ms.risk_number > 3:
        logging.info(ms.comment)
        target_ms.add(ms)

all_csg_reports = set()

# TODO: could stop the search when all CSG-Threat pairs have been found?

logging.info("Computing explanations...")
for ms in target_ms:
    explanation = ms.explain_likelihood()
    timer.log()
    for csg_report in explanation["csg_reports"]:
        csg_report_copy = copy.copy(csg_report)
        csg_report_copy.misbehaviour = ms
        all_csg_reports.add(csg_report_copy)

with open(output_filename, 'w', newline='') as file:
    writer = csv.writer(file)
    # Write the header
    writer.writerow(ControlStrategyReport.cvs_header())
    # Write each row
    for csg_report in all_csg_reports:
        writer.writerow(csg_report.csv_row())

# TODO: include root causes that are not controlled at all on their path to the MS