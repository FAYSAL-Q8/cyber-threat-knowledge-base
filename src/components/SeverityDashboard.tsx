import React, { useEffect, useRef, useMemo } from 'react';
import * as d3 from 'd3';
import { Activity } from 'lucide-react';
import { Vulnerability } from '../types';

interface SeverityDataPoint {
  severity: string;
  count: number;
}

interface SeverityDashboardProps {
  filteredVulnerabilities: Vulnerability[];
}

export default function SeverityDashboard({ filteredVulnerabilities }: SeverityDashboardProps) {
  const svgRef = useRef<SVGSVGElement | null>(null);

  // Classify severities dynamically based on current filtered records
  const severityData = useMemo<SeverityDataPoint[]>(() => {
    const counts: { [key: string]: number } = {
      'Critical': 0,
      'High': 0,
      'Medium': 0,
      'Low': 0,
    };

    // Initialize all to make sure we show them in the chart
    filteredVulnerabilities.forEach(v => {
      const sev = v.severity || 'Medium';
      if (counts[sev] !== undefined) {
        counts[sev]++;
      } else {
        counts[sev] = (counts[sev] || 0) + 1;
      }
    });

    return Object.entries(counts).map(([severity, count]) => ({
      severity,
      count
    }));
  }, [filteredVulnerabilities]);

  const totalCount = filteredVulnerabilities.length;

  useEffect(() => {
    if (!svgRef.current) return;

    // Clear previous SVG contents
    const svgElement = d3.select(svgRef.current);
    svgElement.selectAll('*').remove();

    const width = 320;
    const height = 150;
    const margin = { top: 10, right: 35, bottom: 20, left: 60 };

    svgElement
      .attr('width', '100%')
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('style', 'max-width: 100%; height: auto;');

    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;

    const g = svgElement
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Scale X - linear scale based on bar values
    const maxVal = d3.max(severityData, (d: SeverityDataPoint) => d.count) || 1;
    // Ensure we start at 0, and have at least 1 tick
    const xMax = Math.max(maxVal, 2);

    const xScale = d3.scaleLinear()
      .domain([0, xMax])
      .range([0, chartWidth]);

    // Scale Y - band scale for categories
    const yScale = d3.scaleBand()
      .domain(severityData.map(d => d.severity))
      .range([0, chartHeight])
      .padding(0.25);

    // Color mapper with high-contrast choices
    // Uses CSS custom properties and standard hex values that adapt perfectly
    const getColor = (severity: string) => {
      switch (severity) {
        case 'Critical':
          return 'var(--color-critical, #EF4444)';
        case 'High':
          return 'var(--color-high, #F59E0B)';
        case 'Medium':
          return 'var(--color-medium, #EAB308)';
        case 'Low':
          return 'var(--color-low, #10B981)';
        default:
          return '#6B7280';
      }
    };

    // Draw background tracks for visual gauge feeling
    g.selectAll('.track-rect')
      .data(severityData)
      .enter()
      .append('rect')
      .attr('class', 'track-rect')
      .style('fill', 'var(--chart-track)')
      .attr('x', 0)
      .attr('y', (d: SeverityDataPoint) => yScale(d.severity) || 0)
      .attr('width', chartWidth)
      .attr('height', yScale.bandwidth())
      .attr('stroke', 'rgba(255,255,255,0.03)')
      .attr('stroke-width', 1);

    // Filtered grid lines (ticks) for accurate evaluation
    const ticks = xScale.ticks(Math.min(5, xMax));
    g.selectAll('.grid-line')
      .data(ticks)
      .enter()
      .append('line')
      .attr('class', 'grid-line')
      .style('stroke', 'var(--chart-grid)')
      .attr('x1', d => xScale(d))
      .attr('y1', 0)
      .attr('x2', d => xScale(d))
      .attr('y2', chartHeight)
      .attr('stroke-dasharray', '2,2');

    // Create bars group
    const bars = g.selectAll('.bar-rect')
      .data(severityData)
      .enter()
      .append('g')
      .attr('class', 'bar-group');

    // Draw the actual data bars
    bars.append('rect')
      .attr('class', 'bar-rect transition-all duration-300')
      .attr('x', 0)
      .attr('y', (d: SeverityDataPoint) => yScale(d.severity) || 0)
      .attr('height', yScale.bandwidth())
      .attr('fill', (d: SeverityDataPoint) => getColor(d.severity))
      .style('opacity', 0.8)
      // Initial animation state
      .attr('width', 0)
      .transition()
      .duration(700)
      .ease(d3.easeCubicOut)
      .attr('width', (d: SeverityDataPoint) => xScale(d.count));

    // Interactive pointer indicators
    bars.on('mouseover', function(this: any) {
      d3.select(this).select('.bar-rect')
        .style('opacity', 1.0)
        .attr('stroke', '#ffffff')
        .attr('stroke-width', 1.5);
    })
    .on('mouseout', function(this: any) {
      d3.select(this).select('.bar-rect')
        .style('opacity', 0.8)
        .attr('stroke', 'none');
    });

    // Add count values on top of or next to the bars
    bars.append('text')
      .style('fill', 'var(--axis-text-bold)')
      .attr('class', 'font-mono font-bold text-[10.5px]')
      .attr('y', (d: SeverityDataPoint) => (yScale(d.severity) || 0) + yScale.bandwidth() / 2 + 3.5)
      .attr('x', 0)
      // Animate text positioning along with bars
      .transition()
      .duration(700)
      .ease(d3.easeCubicOut)
      .attr('x', (d: SeverityDataPoint) => Math.max(xScale(d.count) + 6, 8))
      .text((d: SeverityDataPoint) => d.count);

    // Left Y Axis labels with custom stylings
    const yAxisGroup = g.append('g')
      .attr('class', 'y-axis-group')
      .call(d3.axisLeft(yScale).tickSize(0));

    yAxisGroup.select('.domain').remove(); // Remove standard dark line
    yAxisGroup.selectAll('text')
      .style('fill', 'var(--axis-text)')
      .attr('class', 'font-mono text-[9.5px] uppercase tracking-wider')
      .attr('dx', -8);

    // Bottom horizontal axis ticks for precision
    const xAxis = d3.axisBottom(xScale)
      .ticks(Math.min(5, xMax))
      .tickFormat(d3.format('d'));

    const xAxisGroup = g.append('g')
      .attr('class', 'x-axis-group')
      .attr('transform', `translate(0, ${chartHeight})`)
      .call(xAxis);

    xAxisGroup.select('.domain').style('stroke', 'var(--chart-grid)');
    xAxisGroup.selectAll('line').style('stroke', 'var(--chart-grid)');
    xAxisGroup.selectAll('text')
      .style('fill', 'var(--axis-text)')
      .attr('class', 'font-mono text-[8px]');

  }, [severityData]);

  return (
    <div className="bg-black border border-zinc-200 dark:border-white/10 p-5 flex flex-col gap-4">
      {/* Custom Theme Color Variables mapped for light/dark mode overrides */}
      <style>{`
        .light {
          --color-critical: #E11D48;
          --color-high: #EA580C;
          --color-medium: #D97706;
          --color-low: #059669;
          --axis-text: #4E555C;
          --axis-text-bold: #111827;
          --chart-track: #F3F4F6;
          --chart-grid: #E5E7EB;
        }
        .dark {
          --color-critical: #EF4444;
          --color-high: #F97316;
          --color-medium: #CCFF00;
          --color-low: #10B981;
          --axis-text: #A1A1AA;
          --axis-text-bold: #F3F4F6;
          --chart-track: #09090B;
          --chart-grid: rgba(255, 255, 255, 0.04);
        }
      `}</style>

      <div className="flex items-center justify-between border-b border-zinc-200 dark:border-white/5 pb-2.5">
        <span className="font-mono text-xs uppercase tracking-widest text-[#121415] dark:text-[#CCFF00] flex items-center gap-1.5 font-bold">
          <Activity className="w-3.5 h-3.5 text-[#121415] dark:text-[#CCFF00]" />
          [Severity Assessment]
        </span>
        <span className="font-mono text-[9px] text-zinc-500 dark:text-zinc-500 font-semibold uppercase">
          SVG Distribution / D3.JS
        </span>
      </div>

      <div className="flex flex-col gap-3">
        {/* SVG Wrapper with customized dimensions */}
        <div className="bg-zinc-50/50 dark:bg-zinc-950/40 border border-zinc-200 dark:border-white/5 p-2 rounded-xl flex items-center justify-center">
          <svg ref={svgRef}></svg>
        </div>

        {/* Dynamic Summary Cards to ensure clarity of numbers */}
        <div className="grid grid-cols-4 gap-1.5 h-12 font-mono text-center">
          {severityData.map((d) => {
            let labelColor = 'text-zinc-500 dark:text-zinc-400';
            let bgStyle = 'bg-zinc-50 dark:bg-zinc-900/40 border-zinc-200 dark:border-white/5';

            if (d.severity === 'Critical') {
              labelColor = 'text-red-700 dark:text-red-400 font-bold';
              bgStyle = 'bg-red-50/50 dark:bg-red-500/5 border-red-100 dark:border-red-500/20';
            } else if (d.severity === 'High') {
              labelColor = 'text-orange-700 dark:text-orange-400 font-bold';
              bgStyle = 'bg-orange-50/50 dark:bg-orange-500/5 border-orange-100 dark:border-orange-500/20';
            } else if (d.severity === 'Medium') {
              labelColor = 'text-amber-700 dark:text-[#CCFF00] font-bold';
              bgStyle = 'bg-amber-50/50 dark:bg-[#CCFF00]/5 border-amber-100 dark:border-[#CCFF00]/20';
            } else if (d.severity === 'Low') {
              labelColor = 'text-emerald-700 dark:text-emerald-400 font-bold';
              bgStyle = 'bg-emerald-50/50 dark:bg-emerald-500/5 border-emerald-100 dark:border-emerald-500/20';
            }

            const percentage = totalCount > 0 ? Math.round((d.count / totalCount) * 100) : 0;

            return (
              <div key={d.severity} className={`border p-1.5 flex flex-col justify-center items-center ${bgStyle}`}>
                <span className="text-[8px] text-zinc-500 dark:text-zinc-500 tracking-wider uppercase block">{d.severity}</span>
                <span className={`text-xs sm:text-sm leading-tight ${labelColor}`}>{d.count}</span>
                <span className="text-[7.5px] text-zinc-650 dark:text-zinc-500 tracking-tight">{percentage}%</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
