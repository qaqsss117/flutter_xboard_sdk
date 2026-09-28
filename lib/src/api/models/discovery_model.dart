/// Public links shared by the client discovery surfaces.
class DiscoveryCatalog {
  static const defaultLandingPageUrl = 'https://vpn.donghuyun.top';
  static const categories = ['search', 'video', 'social', 'ai', 'developer'];

  const DiscoveryCatalog({
    this.landingPageUrl = defaultLandingPageUrl,
    this.sites = const [],
  });

  final String landingPageUrl;
  final List<DiscoverySite> sites;

  /// Optional discovery data must not make authentication decoding fail.
  factory DiscoveryCatalog.fromJson(Object? value) {
    if (value is! Map) return const DiscoveryCatalog();
    final ids = <int>{};
    final entries = value['sites'];
    final sites = entries is List
        ? entries
              .map(DiscoverySite.tryFromJson)
              .whereType<DiscoverySite>()
              .where((site) => ids.add(site.id))
              .toList()
        : <DiscoverySite>[];
    sites.sort((a, b) {
      final category = categories
          .indexOf(a.category)
          .compareTo(categories.indexOf(b.category));
      if (category != 0) return category;
      final order = a.sortOrder.compareTo(b.sortOrder);
      return order != 0 ? order : a.id.compareTo(b.id);
    });
    return DiscoveryCatalog(
      landingPageUrl:
          httpsUri(value['landing_page_url'])?.toString() ??
          defaultLandingPageUrl,
      sites: List.unmodifiable(sites),
    );
  }

  Map<String, dynamic> toJson() => {
    'landing_page_url': landingPageUrl,
    'sites': sites.map((site) => site.toJson()).toList(),
  };

  static Map<String, dynamic> encode(DiscoveryCatalog value) => value.toJson();

  static Uri? httpsUri(Object? value) {
    if (value is! String ||
        value.isEmpty ||
        RegExp(r'[\s\\\x00-\x1f\x7f]').hasMatch(value)) {
      return null;
    }
    final uri = Uri.tryParse(value);
    if (uri == null ||
        uri.scheme != 'https' ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        uri.port < 1 ||
        uri.port > 65535) {
      return null;
    }
    return uri;
  }
}

class DiscoverySite {
  const DiscoverySite({
    required this.id,
    required this.name,
    required this.url,
    required this.category,
    this.description = '',
    this.sortOrder = 0,
  });

  final int id;
  final String name;
  final String url;
  final String description;
  final String category;
  final int sortOrder;

  static DiscoverySite? tryFromJson(Object? value) {
    if (value is! Map) return null;
    final id = value['id'];
    final name = value['name'];
    final category = value['category'];
    final uri = DiscoveryCatalog.httpsUri(value['url']);
    if (id is! int ||
        id <= 0 ||
        name is! String ||
        name.trim().isEmpty ||
        category is! String ||
        !DiscoveryCatalog.categories.contains(category) ||
        uri == null ||
        value['enabled'] == false) {
      return null;
    }
    return DiscoverySite(
      id: id,
      name: name.trim(),
      url: uri.toString(),
      category: category,
      description: value['description'] is String
          ? value['description'] as String
          : '',
      sortOrder: value['sort_order'] is int ? value['sort_order'] as int : 0,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'name': name,
    'url': url,
    'description': description,
    'category': category,
    'sort_order': sortOrder,
  };
}
