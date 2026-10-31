import AboutHero from '../components/about/AboutHero';
import WhyTrustPack from '../components/about/WhyTrustPack';
import WorkflowSection from '../components/about/WorkflowSection';
import AnalysisEngine from '../components/about/AnalysisEngine';
import RiskIndicators from '../components/about/RiskIndicators';
import Reveal from '../components/about/Reveal';

export default function About() {
  return (
    <div className="space-y-14 sm:space-y-16">
      <AboutHero />
      <Reveal><WhyTrustPack /></Reveal>
      <Reveal><WorkflowSection /></Reveal>
      <Reveal><AnalysisEngine /></Reveal>
      <Reveal><RiskIndicators /></Reveal>
    </div>
  );
}
