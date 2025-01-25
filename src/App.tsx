import React from 'react';
import { Shield, Wifi, WifiOff } from 'lucide-react';
import { SearchBar } from './components/SearchBar';
import { ProtocolFilter } from './components/ProtocolFilter';
import { PacketTable } from './components/PacketTable';
import { AdminPanel } from './components/admin/AdminPanel';
import { usePackets } from './hooks/usePackets';
import { StatusFilter } from './components/StatusFilter';

export default function App() {
  const {
    packets,
    searchTerm,
    setSearchTerm,
    selectedProtocol,
    setSelectedProtocol,
    showOnlySuspicious,
    setShowOnlySuspicious,
    isConnected
  } = usePackets();

  return (
    <div className="min-h-screen bg-gray-100">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center">
            <Shield className="h-8 w-8 text-blue-600 mr-3" />
            <div>
              <h1 className="text-2xl font-bold text-gray-900">
                Network Security Analysis Platform
              </h1>
              <p className="text-sm text-gray-500 mt-1">by Silent Guardian</p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            {isConnected ? (
              <Wifi className="h-5 w-5 text-green-500" />
            ) : (
              <WifiOff className="h-5 w-5 text-red-500" />
            )}
            <span className={`text-sm ${isConnected ? 'text-green-500' : 'text-red-500'}`}>
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>

        <div className="space-y-6">
          <AdminPanel />

          <div className="bg-white rounded-lg shadow-sm p-6">
            <div className="flex flex-wrap gap-4 mb-6">
              <div className="flex-1 min-w-[300px]">
                <SearchBar
                  value={searchTerm}
                  onChange={setSearchTerm}
                  onClear={() => setSearchTerm('')}
                />
              </div>
              <div className="flex gap-4">
                <ProtocolFilter
                  value={selectedProtocol}
                  onChange={setSelectedProtocol}
                />
                <StatusFilter
                  value={showOnlySuspicious}
                  onChange={setShowOnlySuspicious}
                />
              </div>
            </div>

            <PacketTable packets={packets} />
          </div>
        </div>
      </div>
    </div>
  );
}