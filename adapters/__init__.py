"""IronMesh framework adapters.

Thin wrappers that make IronMesh a native tool in popular agent
frameworks. Each adapter is an optional dependency — install the
framework first, then import the adapter.

Available adapters:
- ``ironmesh.adapters.langchain_adapter`` — LangChain BaseTool wrappers
- ``ironmesh.adapters.crewai_adapter`` — CrewAI agent factory (reuses LangChain tools)
- ``ironmesh.adapters.autogen_adapter`` — AutoGen function_map registration
"""
