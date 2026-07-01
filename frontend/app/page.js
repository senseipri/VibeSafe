import Nav from '@/components/vibesafe/Nav';
import Hero from '@/components/vibesafe/Hero';
import CrisisMarquee from '@/components/vibesafe/CrisisMarquee';
import HowItWorks from '@/components/vibesafe/HowItWorks';
import LiveDemo from '@/components/vibesafe/LiveDemo';
import VulnerabilityCatalog from '@/components/vibesafe/VulnerabilityCatalog';
import Pricing from '@/components/vibesafe/Pricing';
import Comparison from '@/components/vibesafe/Comparison';
import FAQ from '@/components/vibesafe/FAQ';
import FinalCTA from '@/components/vibesafe/FinalCTA';
import Footer from '@/components/vibesafe/Footer';

export default function App() {
  return (
    <>
      <Nav />
      <main id="main">
        <Hero />
        <CrisisMarquee />
        <HowItWorks />
        <LiveDemo />
        <VulnerabilityCatalog />
        <Pricing />
        <Comparison />
        <FAQ />
        <FinalCTA />
      </main>
      <Footer />
    </>
  );
}
