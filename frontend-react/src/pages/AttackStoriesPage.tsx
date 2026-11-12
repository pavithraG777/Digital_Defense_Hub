import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, Clock3, FileWarning, Pause, Play, RefreshCw, Search, ShieldAlert, Target, Volume2 } from "lucide-react";
import { api } from "../lib/api";
import {
  EmptyState,
  ErrorBanner,
  FactGrid,
  LoadingState,
  MetricCard,
  StatusBadge,
  formatDate,
  humanize,
  isMap,
  safeFacts,
  type UnknownMap,
} from "./securityOperationsUI";
import "./securityOperations.css";

type StorySummary = {
  story_count: number;
  event_count: number;
  high_or_critical_events: number;
};

type StoryTimelineRow = {
  story_id: string;
  story_title: string;
  event: UnknownMap;
};

type MitreOccurrence = {
  technique: string;
  occurrences: number;
};

type StoryGroup = {
  id: string;
  title: string;
  events: UnknownMap[];
  firstAt?: string;
  lastAt?: string;
  highestSeverity: string;
};

const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];
const excludedEventFields = new Set([
  "title",
  "event_title",
  "description",
  "summary",
  "timestamp",
  "occurred_at",
  "created_at",
  "severity",
  "mitre_technique",
]);

function eventString(event: UnknownMap, keys: string[], fallback = "") {
  for (const key of keys) {
    const value = event[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return fallback;
}

function eventTimestamp(event: UnknownMap) {
  return eventString(event, ["timestamp", "occurred_at", "created_at"]);
}

function eventSeverity(event: UnknownMap) {
  return eventString(event, ["severity"], "UNKNOWN").toUpperCase();
}

function eventTitle(event: UnknownMap) {
  return eventString(event, ["title", "event_title", "event_type", "type", "action"], "Security event");
}

function eventDescription(event: UnknownMap) {
  return eventString(event, ["description", "summary", "finding"], "No narrative was recorded for this event.");
}

function eventTechnique(event: UnknownMap) {
  return eventString(event, ["mitre_technique", "technique"]);
}

function nestedEventValue(event: UnknownMap, keys: string[]) {
  const direct = eventString(event, keys);
  if (direct) return direct;
  const metadata = isMap(event.metadata) ? event.metadata : null;
  return metadata ? eventString(metadata, keys) : "";
}

function eventFileIdentity(event: UnknownMap) {
  return nestedEventValue(event, ["canary_file_id", "protected_file_id", "file_id", "file_path", "file_name"]);
}

function eventFileLabel(event: UnknownMap) {
  return nestedEventValue(event, ["file_name", "original_file_name", "file_path", "canary_file_id"]) || "Unidentified security resource";
}

function eventNarration(event: UnknownMap, index: number, total: number) {
  const file = eventFileLabel(event);
  const title = humanize(eventTitle(event));
  const severity = humanize(eventSeverity(event));
  const description = eventDescription(event);
  const technique = eventTechnique(event);
  return `Event ${index + 1} of ${total}. ${title}, on ${file}. Severity ${severity}. ${description}${technique ? ` MITRE technique ${technique}.` : ""}`;
}

function severityRank(value: string) {
  const rank = severityOrder.indexOf(value.toUpperCase());
  return rank < 0 ? severityOrder.length : rank;
}

function groupStories(rows: StoryTimelineRow[]): StoryGroup[] {
  const grouped = new Map<string, StoryGroup>();
  for (const row of rows) {
    if (!row || !row.story_id || !isMap(row.event)) continue;
    const fileIdentity = eventFileIdentity(row.event);
    const groupID = fileIdentity ? `file:${fileIdentity.toLowerCase()}` : `story:${row.story_id}`;
    const current = grouped.get(groupID) || {
      id: groupID,
      title: fileIdentity ? `${eventFileLabel(row.event)} · Access story` : row.story_title || "Untitled attack story",
      events: [],
      highestSeverity: "UNKNOWN",
    };
    const fingerprint = eventString(row.event, ["event_id", "id", "event_code"]) || `${eventTimestamp(row.event)}:${eventTitle(row.event)}`;
    if (!current.events.some((event) => (eventString(event, ["event_id", "id", "event_code"]) || `${eventTimestamp(event)}:${eventTitle(event)}`) === fingerprint)) current.events.push(row.event);
    const severity = eventSeverity(row.event);
    if (severityRank(severity) < severityRank(current.highestSeverity)) current.highestSeverity = severity;
    grouped.set(groupID, current);
  }

  return [...grouped.values()]
    .map((story) => {
      const events = [...story.events].sort((left, right) => {
        const leftTime = Date.parse(eventTimestamp(left));
        const rightTime = Date.parse(eventTimestamp(right));
        if (Number.isNaN(leftTime) || Number.isNaN(rightTime)) return 0;
        return leftTime - rightTime;
      });
      return {
        ...story,
        events,
        firstAt: eventTimestamp(events[0]),
        lastAt: eventTimestamp(events[events.length - 1]),
      };
    })
    .sort((left, right) => Date.parse(right.lastAt || "") - Date.parse(left.lastAt || ""));
}

function eventFacts(event: UnknownMap) {
  const remaining = Object.fromEntries(Object.entries(event).filter(([key]) => !excludedEventFields.has(key)));
  return safeFacts(remaining);
}

export function AttackStoriesPage() {
  const [summary, setSummary] = useState<StorySummary | null>(null);
  const [rows, setRows] = useState<StoryTimelineRow[]>([]);
  const [mitre, setMitre] = useState<MitreOccurrence[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [techniqueFilter, setTechniqueFilter] = useState("");
  const [selectedStoryID, setSelectedStoryID] = useState("");
  const [eventIndex, setEventIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const narrationRef = useRef<SpeechSynthesisUtterance | null>(null);

  const load = useCallback(async (refresh = false) => {
    refresh ? setRefreshing(true) : setLoading(true);
    setError(null);
    try {
      const [summaryData, timelineData, mitreData] = await Promise.all([
        api.get<StorySummary>("/attackstory/summary"),
        api.get<StoryTimelineRow[]>("/attackstory/timeline"),
        api.get<MitreOccurrence[]>("/attackstory/mitre"),
      ]);
      setSummary(summaryData);
      setRows(Array.isArray(timelineData) ? timelineData : []);
      setMitre(Array.isArray(mitreData) ? mitreData : []);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to load attack stories");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const stories = useMemo(() => groupStories(rows), [rows]);
  const filteredStories = useMemo(() => {
    const query = search.trim().toLowerCase();
    return stories.filter((story) => {
      const searchMatch = !query || story.title.toLowerCase().includes(query) || story.events.some((event) => {
        return [eventTitle(event), eventDescription(event), eventTechnique(event)].some((value) => value.toLowerCase().includes(query));
      });
      const severityMatch = !severityFilter || story.events.some((event) => eventSeverity(event) === severityFilter);
      const techniqueMatch = !techniqueFilter || story.events.some((event) => eventTechnique(event) === techniqueFilter);
      return searchMatch && severityMatch && techniqueMatch;
    });
  }, [search, severityFilter, stories, techniqueFilter]);

  useEffect(() => {
    if (!filteredStories.length) {
      setSelectedStoryID("");
      setEventIndex(0);
      setPlaying(false);
      return;
    }
    if (!filteredStories.some((story) => story.id === selectedStoryID)) {
      setSelectedStoryID(filteredStories[0].id);
      setEventIndex(0);
      setPlaying(false);
    }
  }, [filteredStories, selectedStoryID]);

  const selectedStory = filteredStories.find((story) => story.id === selectedStoryID) || null;
  const selectedEvent = selectedStory?.events[eventIndex] || null;

  useEffect(() => {
    if (!playing || !selectedStory || !selectedEvent) return;
    let active = true;
    const advance = () => {
      if (!active) return;
      if (eventIndex >= selectedStory.events.length - 1) setPlaying(false);
      else setEventIndex((current) => current + 1);
    };
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(eventNarration(selectedEvent, eventIndex, selectedStory.events.length));
    const voices = window.speechSynthesis.getVoices();
    utterance.voice = voices.find((voice) => voice.lang.toLowerCase() === "en-in") || voices.find((voice) => voice.lang.toLowerCase().startsWith("en")) || null;
    utterance.rate = speed === 4 ? 1.55 : speed === 2 ? 1.25 : 1;
    utterance.pitch = .92;
    utterance.volume = 1;
    utterance.onend = advance;
    utterance.onerror = advance;
    narrationRef.current = utterance;
    window.speechSynthesis.speak(utterance);
    return () => { active = false; if (narrationRef.current === utterance) window.speechSynthesis.cancel(); };
  }, [eventIndex, playing, selectedEvent, selectedStory, speed]);

  useEffect(() => () => window.speechSynthesis?.cancel(), []);

  const severityCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const row of rows) {
      const severity = eventSeverity(row.event);
      counts.set(severity, (counts.get(severity) || 0) + 1);
    }
    return severityOrder.map((severity) => ({ severity, count: counts.get(severity) || 0 })).filter((item) => item.count > 0);
  }, [rows]);

  const totalSeverityEvents = severityCounts.reduce((sum, item) => sum + item.count, 0);
  const donut = totalSeverityEvents
    ? severityCounts.reduce<{ stops: string[]; offset: number }>((result, item) => {
        const start = result.offset;
        const width = (item.count / totalSeverityEvents) * 100;
        const colors: Record<string, string> = { CRITICAL: "#ff445f", HIGH: "#ff8b36", MEDIUM: "#f6c94c", LOW: "#35d586", INFO: "#37a7ff", UNKNOWN: "#7890a8" };
        result.stops.push(`${colors[item.severity] || colors.UNKNOWN} ${start}% ${start + width}%`);
        result.offset += width;
        return result;
      }, { stops: [], offset: 0 }).stops.join(", ")
    : "#13283d 0 100%";

  const maxMitre = Math.max(0, ...mitre.map((item) => item.occurrences));
  const techniqueOptions = [...new Set(mitre.map((item) => item.technique).filter(Boolean))].sort();

  function selectStory(story: StoryGroup) {
    window.speechSynthesis?.cancel();
    setSelectedStoryID(story.id);
    setEventIndex(0);
    setPlaying(false);
  }

  function toggleReplay() {
    if (playing) {
      window.speechSynthesis?.cancel();
      setPlaying(false);
      return;
    }
    if (selectedStory && eventIndex >= selectedStory.events.length - 1) setEventIndex(0);
    setPlaying(true);
  }

  return (
    <section className="soc-ops-page soc-story-page">
      <header className="soc-ops-hero">
        <div><p>ATTACK CHAIN INTELLIGENCE</p><h1>Attack Stories</h1><span>Replay correlated security events exactly as recorded by the backend.</span></div>
        <button className="secondary" type="button" onClick={() => void load(true)} disabled={refreshing}><RefreshCw className={refreshing ? "spin" : ""} size={17} /> {refreshing ? "Refreshing…" : "Refresh"}</button>
      </header>

      <div className="soc-filterbar soc-story-filters">
        <label className="soc-search"><Search size={17} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search story, event or technique" /></label>
        <label>Severity<select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="">All severities</option>{severityOrder.slice(0, -1).map((item) => <option key={item}>{item}</option>)}</select></label>
        <label>MITRE technique<select value={techniqueFilter} onChange={(event) => setTechniqueFilter(event.target.value)}><option value="">All mapped techniques</option>{techniqueOptions.map((item) => <option key={item}>{item}</option>)}</select></label>
      </div>

      {error ? <ErrorBanner message={error} /> : null}
      {loading ? <LoadingState label="Loading attack-story timeline…" /> : null}
      {!loading && !error ? <>
        <div className="soc-metrics">
          <MetricCard label="File stories" value={stories.length} hint="Events grouped by the same file / Canary" accent="blue" />
          <MetricCard label="Timeline events" value={summary?.event_count ?? rows.length} hint="Recorded correlated events" accent="violet" />
          <MetricCard label="High / critical" value={summary?.high_or_critical_events ?? 0} hint="Backend severity count" accent="red" />
          <MetricCard label="MITRE techniques" value={mitre.length} hint="Techniques present in story data" accent="amber" />
          <MetricCard label="Visible stories" value={filteredStories.length} hint="After current filters" accent="green" />
        </div>

        {!stories.length ? <EmptyState title="No attack stories recorded" message="The backend returned no attack-story timeline events for this organization." /> : <>
          <div className="soc-story-overview">
            <section className="soc-panel soc-story-list-panel">
              <header><div><p>FILE-CORRELATED NARRATIVES</p><h2>Recorded file stories</h2></div><span>{filteredStories.length} visible</span></header>
              <div className="soc-story-list">
                {filteredStories.map((story) => <button key={story.id} type="button" className={story.id === selectedStoryID ? "active" : ""} onClick={() => selectStory(story)}>
                  <span className="soc-story-icon"><FileWarning size={18} /></span>
                  <span><strong>{story.title}</strong><small>{story.events.length} event{story.events.length === 1 ? "" : "s"} · Last {formatDate(story.lastAt)}</small></span>
                  <StatusBadge value={story.highestSeverity} />
                </button>)}
                {!filteredStories.length ? <p className="soc-muted">No story matches the selected filters.</p> : null}
              </div>
            </section>

            <section className="soc-panel soc-story-replay">
              {selectedStory && selectedEvent ? <>
                <header><div><p>EVENT REPLAY</p><h2>{selectedStory.title}</h2></div><StatusBadge value={eventSeverity(selectedEvent)} /></header>
                <div className="soc-replay-controls">
                  <button type="button" className="icon-button" aria-label="Previous event" disabled={eventIndex === 0} onClick={() => { window.speechSynthesis?.cancel(); setPlaying(false); setEventIndex((current) => Math.max(0, current - 1)); }}><ChevronLeft size={18} /></button>
                  <button type="button" className="primary soc-play" onClick={toggleReplay}>{playing ? <Pause size={17} /> : <Play size={17} />} {playing ? "Pause voice" : "AI voice replay"}</button>
                  <button type="button" className="icon-button" aria-label="Next event" disabled={eventIndex >= selectedStory.events.length - 1} onClick={() => { window.speechSynthesis?.cancel(); setPlaying(false); setEventIndex((current) => Math.min(selectedStory.events.length - 1, current + 1)); }}><ChevronRight size={18} /></button>
                  <label>Speed<select value={speed} onChange={(event) => setSpeed(Number(event.target.value))}><option value={1}>1×</option><option value={2}>2×</option><option value={4}>4×</option></select></label>
                  <span>Event {eventIndex + 1} of {selectedStory.events.length}</span>
                </div>
                <div className={`soc-narration-status${playing ? " speaking" : ""}`}><Volume2 size={16}/><span>{playing ? `Narrating event ${eventIndex + 1}; the next event starts after narration finishes` : "Voice narration ready"}</span></div>
                <div className="soc-replay-track" aria-label="Attack story event timeline">
                  {selectedStory.events.map((event, index) => <button key={`${eventTimestamp(event)}-${index}`} type="button" className={index === eventIndex ? "active" : index < eventIndex ? "complete" : ""} onClick={() => { window.speechSynthesis?.cancel(); setPlaying(false); setEventIndex(index); }} title={eventTitle(event)}><i /><span>{index + 1}</span><small>{humanize(eventTitle(event))}</small></button>)}
                </div>
                <article className="soc-current-event">
                  <div className="soc-current-event-heading"><span><Clock3 size={17} /> {formatDate(eventTimestamp(selectedEvent))}</span>{eventTechnique(selectedEvent) ? <span><Target size={17} /> {eventTechnique(selectedEvent)}</span> : null}</div>
                  <h3>{humanize(eventTitle(selectedEvent))}</h3>
                  <p>{eventDescription(selectedEvent)}</p>
                  <FactGrid facts={eventFacts(selectedEvent)} empty="No additional non-sensitive event evidence was recorded." />
                </article>
              </> : <EmptyState title="Select an attack story" message="Choose a recorded story to inspect its event sequence." />}
            </section>
          </div>

          <div className="soc-visual-grid soc-story-analytics">
            <section className="soc-panel soc-severity-panel"><header><div><p>EVENT EXPOSURE</p><h2>Severity distribution</h2></div><ShieldAlert size={20} /></header>{totalSeverityEvents ? <div className="soc-donut-row"><div className="soc-donut" style={{ background: `conic-gradient(${donut})` }}><span><strong>{totalSeverityEvents}</strong><small>Events</small></span></div><div className="soc-legend">{severityCounts.map((item) => <div key={item.severity}><StatusBadge value={item.severity} /><strong>{item.count}</strong></div>)}</div></div> : <p className="soc-muted">No event severities were returned.</p>}</section>
            <section className="soc-panel"><header><div><p>TACTIC COVERAGE</p><h2>MITRE technique occurrences</h2></div><Target size={20} /></header>{mitre.length ? <div className="soc-bars">{[...mitre].sort((left, right) => right.occurrences - left.occurrences).map((item) => <div key={item.technique}><span>{item.technique}</span><i><b style={{ width: `${maxMitre ? (item.occurrences / maxMitre) * 100 : 0}%` }} /></i><strong>{item.occurrences}</strong></div>)}</div> : <p className="soc-muted">No MITRE techniques are present in the recorded story events.</p>}</section>
          </div>
        </>}
      </> : null}
    </section>
  );
}
