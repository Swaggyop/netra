"use client";
import Sidebar from "@/components/Sidebar";
import TopBar from "@/components/TopBar";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex w-full min-h-screen bg-background">
      <Sidebar />
      <div className="ml-[220px] flex flex-col flex-1 min-h-screen">
        <TopBar alertCount={5} />
        <main className="flex-1 px-6 py-8 max-w-[1440px] w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
