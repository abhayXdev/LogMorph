
function App() {
  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
      <div className="bg-slate-900 border border-cyan-500/30 rounded-2xl p-10 text-center shadow-xl">
        <h1 className="text-4xl font-bold text-cyan-400">
          LogMorph
        </h1>

        <p className="text-gray-300 mt-4">
          React + TypeScript + Tailwind CSS
        </p>

        <button className="mt-6 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold px-6 py-3 rounded-lg transition-colors">
          Setup Successful
        </button>
      </div>
    </div>
  )
}

export default App
