import networkx as nx
import matplotlib.pyplot as plt

# Create a directed graph
graph = nx.DiGraph()

# Add nodes with their types
graph.add_node('dc', type='host', label='Data Center', region='dc')
graph.add_node('dcs1', type='switch', label='Data Center Switch', region='dc')
graph.add_node('cc1', type='cc', label='Cluster Center 1 (Hostel)', region='cc1')
graph.add_node('cc2', type='cc', label='Cluster Center 2 (Academic Area)', region='cc2')
graph.add_node('cc3', type='cc', label='Cluster Center 3 (Sports Complex)', region='cc3')
graph.add_node('r1', type='router', label='Router 1', region='core')
graph.add_node('r2', type='router', label='Router 2', region='core')
graph.add_node('s1_cc1', type='switch_cc', label='Switch 1 (cc1)', region='cc1')
graph.add_node('s2_cc1', type='switch_cc', label='Switch 2 (cc1)', region='cc1')
graph.add_node('s1_cc1_h', type='host_cc', label='Switch 1 (cc1) host', region='cc1')
graph.add_node('s2_cc1_h', type='host_cc', label='Switch 2 (cc1) host', region='cc1')
graph.add_node('s1_cc2', type='switch_cc', label='Switch 1 (cc2)', region='cc2')
graph.add_node('s2_cc2', type='switch_cc', label='Switch 2 (cc2)', region='cc2')
graph.add_node('s1_cc2_h', type='host_cc', label='Switch 1 (cc2) host', region='cc2')
graph.add_node('s2_cc2_h', type='host_cc', label='Switch 2 (cc2) host', region='cc2')
graph.add_node('s1_cc3', type='switch_cc', label='Switch 1 (cc3)', region='cc3')
graph.add_node('s2_cc3', type='switch_cc', label='Switch 2 (cc3) host', region='cc3')
graph.add_node('s1_cc3_h', type='host_cc', label='Switch 1 (cc3) host', region='cc3')
graph.add_node('s2_cc3_h', type='host_cc', label='Switch 2 (cc3) host', region='cc3')

for i in range(1, 9):
    graph.add_node(f'h{i}_cc1', type='host_regular_cc1', label=f'User {i}', region='cc1')
    graph.add_node(f'h{i}_cc2', type='host_regular_cc2', label=f'User {8 + i}', region='cc2')
    graph.add_node(f'h{i}_cc3', type='host_regular_cc3', label=f'User {16 + i}', region='cc3')

# Add edges based on the links
graph.add_edge('dc', 'dcs1')
graph.add_edge('dcs1', 'dc')

graph.add_edge('cc1', 'dcs1')
graph.add_edge('dcs1', 'cc1')

graph.add_edge('cc2', 'dcs1')
graph.add_edge('dcs1', 'cc2')

graph.add_edge('cc3', 'dcs1')
graph.add_edge('dcs1', 'cc3')

graph.add_edge('cc1', 's1_cc1')
graph.add_edge('s1_cc1', 'cc1')

graph.add_edge('s1_cc1_h', 's1_cc1')
graph.add_edge('s1_cc1', 's1_cc1_h')

graph.add_edge('s2_cc1_h', 's2_cc1')
graph.add_edge('s2_cc1', 's2_cc1_h')

graph.add_edge('s1_cc1', 'r1')
graph.add_edge('r1', 's1_cc1')

graph.add_edge('s1_cc1', 's2_cc1')
graph.add_edge('s2_cc1', 's1_cc1')

for i in range(1, 9):
    if i <= 4:
        graph.add_edge(f'h{i}_cc1', 's1_cc1')
        graph.add_edge('s1_cc1', f'h{i}_cc1')
    else:
        graph.add_edge(f'h{i}_cc1', 's2_cc1')
        graph.add_edge('s2_cc1', f'h{i}_cc1')

graph.add_edge('cc2', 's1_cc2')
graph.add_edge('s1_cc2', 'cc2')

graph.add_edge('s1_cc2_h', 's1_cc2')
graph.add_edge('s1_cc2', 's1_cc2_h')

graph.add_edge('s2_cc2_h', 's2_cc2')
graph.add_edge('s2_cc2', 's2_cc2_h')

graph.add_edge('s1_cc2', 'r1')
graph.add_edge('r1', 's1_cc2')

graph.add_edge('s1_cc2', 'r2')
graph.add_edge('r2', 's1_cc2')

graph.add_edge('s1_cc2', 's2_cc2')
graph.add_edge('s2_cc2', 's1_cc2')

for i in range(1, 9):
    if i <= 4:
        graph.add_edge(f'h{i}_cc2', 's1_cc2')
        graph.add_edge('s1_cc2', f'h{i}_cc2')
    else:
        graph.add_edge(f'h{i}_cc2', 's2_cc2')
        graph.add_edge('s2_cc2', f'h{i}_cc2')

graph.add_edge('cc3', 's1_cc3')
graph.add_edge('s1_cc3', 'cc3')

graph.add_edge('s1_cc3_h', 's1_cc3')
graph.add_edge('s1_cc3', 's1_cc3_h')

graph.add_edge('s2_cc3_h', 's2_cc3')
graph.add_edge('s2_cc3', 's2_cc3_h')

graph.add_edge('s1_cc3', 'r2')
graph.add_edge('r2', 's1_cc3')

graph.add_edge('s1_cc3', 's2_cc3')
graph.add_edge('s2_cc3', 's1_cc3')

for i in range(1, 9):
    if i <= 4:
        graph.add_edge(f'h{i}_cc3', 's1_cc3')
        graph.add_edge('s1_cc3', f'h{i}_cc3')
    else:
        graph.add_edge(f'h{i}_cc3', 's2_cc3')
        graph.add_edge('s2_cc3', f'h{i}_cc3')

# ADDITIONAL CONNECTIONS TO SECOND SWITCHES
# graph.add_edge('s2_cc1', 'r1')
graph.add_edge('r1', 's2_cc1')

# graph.add_edge('s2_cc2', 'r1')
graph.add_edge('r1', 's2_cc2')

# graph.add_edge('s2_cc2', 'r2')
graph.add_edge('r2', 's2_cc2')

# graph.add_edge('s2_cc3', 'r2')
graph.add_edge('r2', 's2_cc3')

# Define node colors based on type
node_colors = {
    'host': 'orange', 'switch': 'lightblue', 'cc': 'lightgreen',
    'router': 'gold', 'switch_cc': 'lightblue', 'host_cc': 'yellow',
    'host_regular_cc1': 'red', 'host_regular_cc2': 'red', 'host_regular_cc3': 'red'
}
colors = [node_colors[graph.nodes[n]['type']] for n in graph.nodes()]

# Define labels
labels = {n: graph.nodes[n]['label'] for n in graph.nodes()}

# Define regions and their colors
region_colors = {'cc1': 'lightcoral', 'cc2': 'lightcoral', 'cc3': 'lightcoral', 'dc': 'white'}
regions = ['cc1', 'cc2', 'cc3', 'dc']

# Get positions of the nodes
plt.figure(figsize=(20, 15))
pos = nx.spring_layout(graph, seed=42, k=0.7, iterations=300)

# Draw shaded backgrounds for each region
padding = 0.2
for region, color in region_colors.items():
    region_nodes = [n for n, data in graph.nodes(data=True) if data.get('region') == region]
    if region_nodes:
        x_coords = [pos[node][0] for node in region_nodes]
        y_coords = [pos[node][1] for node in region_nodes]
        if x_coords and y_coords:
            min_x, max_x = min(x_coords), max(x_coords)
            min_y, max_y = min(y_coords), max(y_coords)
            width = max_x - min_x
            height = max_y - min_y
            center_x = (min_x + max_x) / 2
            center_y = (min_y + max_y) / 2
            rect = plt.Rectangle((min_x - padding * width, min_y - padding * height),
                                 width * (1 + 2 * padding), height * (1 + 2 * padding),
                                 facecolor=color, alpha=0.3, linewidth=0.5)
            plt.gca().add_patch(rect)

# Draw the nodes with colors
nx.draw_networkx_nodes(graph, pos, node_color=colors, node_size=1200)

# Split edges for curved drawing
curved_edges = []
straight_edges = []

for u, v in graph.edges():
    if ((u.startswith('r') and 's2_' in v) or (v.startswith('r') and 's2_' in u)):
        curved_edges.append((u, v))
    else:
        straight_edges.append((u, v))

# Draw edges
nx.draw_networkx_edges(graph, pos, edgelist=straight_edges, width=1, arrowstyle='->', arrowsize=10)
nx.draw_networkx_edges(graph, pos, edgelist=curved_edges, width=1, arrowstyle='->',
                       arrowsize=10, connectionstyle='arc3,rad=0.3')

# Draw labels
# Draw labels with y-offsets to reduce overlap
adjusted_pos = {}
y_offset = 0.03  # adjust this value to spread labels vertically
for node, (x, y) in pos.items():
    # Slightly nudge node labels upward or downward to avoid clutter
    adjusted_pos[node] = (x, y + y_offset if graph.nodes[node]['type'] in ['router', 'switch'] else y - y_offset)

nx.draw_networkx_labels(graph, adjusted_pos, labels, font_size=10, font_color='black')


# Show plot
plt.title("Scaled Topology for Simulation", fontsize=18)
plt.axis('off')
plt.tight_layout()
plt.show()
